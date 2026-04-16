use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

use crate::event::Event;

/// Errors from the event bus.
#[derive(Debug, thiserror::Error)]
pub enum EventBusError {
    #[error("event bus channel is full, dropping event")]
    ChannelFull,
    #[error("event bus has been shut down")]
    Closed,
}

/// A receiver handle for the event bus.
///
/// Each module gets its own receiver to consume events independently.
pub struct EventReceiver {
    broadcast_rx: broadcast::Receiver<Event>,
}

impl EventReceiver {
    /// Receive the next event from the bus.
    ///
    /// Returns `None` if the bus has been shut down and all pending events
    /// have been consumed.
    pub async fn recv(&mut self) -> Option<Event> {
        loop {
            match self.broadcast_rx.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "event receiver lagged, skipped events");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// The central event bus that connects all agent modules.
///
/// Uses a broadcast channel so every subscriber sees every event.
/// The bus has a bounded capacity; if a slow consumer lags behind,
/// it will skip oldest events rather than block producers.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
    /// Dedicated channel for events that must be forwarded to the server.
    server_tx: mpsc::Sender<Event>,
    capacity: usize,
}

impl EventBus {
    /// Create a new event bus with the given capacity.
    ///
    /// `capacity` controls how many events can be buffered before slow
    /// consumers start lagging.
    /// `server_queue_size` controls the bounded queue for server-bound events.
    pub fn new(capacity: usize, server_queue_size: usize) -> (Self, mpsc::Receiver<Event>) {
        let (tx, _) = broadcast::channel(capacity);
        let (server_tx, server_rx) = mpsc::channel(server_queue_size);

        let bus = Self {
            tx,
            server_tx,
            capacity,
        };

        (bus, server_rx)
    }

    /// Subscribe to the event bus. Returns a receiver that will see all
    /// future events published after this call.
    pub fn subscribe(&self) -> EventReceiver {
        EventReceiver {
            broadcast_rx: self.tx.subscribe(),
        }
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: Event) -> Result<(), EventBusError> {
        // Try to send on broadcast channel
        match self.tx.send(event) {
            Ok(n) => {
                debug!(receivers = n, "event published to bus");
                Ok(())
            }
            Err(_) => {
                // No active receivers -- this is not an error, events are simply
                // dropped if nobody is listening.
                debug!("event published but no receivers active");
                Ok(())
            }
        }
    }

    /// Publish an event and also queue it for server delivery.
    pub async fn publish_to_server(&self, event: Event) -> Result<(), EventBusError> {
        // Queue for server delivery first
        if self.server_tx.try_send(event.clone()).is_err() {
            warn!("server event queue full, dropping event");
            return Err(EventBusError::ChannelFull);
        }

        // Also broadcast to local subscribers
        self.publish(event)
    }

    /// Get the configured capacity of the bus.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

// Ensure EventBus is cheaply cloneable (it's just Arc'd channels internally)
impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("capacity", &self.capacity)
            .field("subscribers", &self.tx.receiver_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, Priority};

    #[tokio::test]
    async fn test_publish_and_receive() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();

        let event = Event::new("test", Priority::Normal, EventKind::Keepalive);
        bus.publish(event).unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await
            .unwrap();

        assert!(received.is_some());
        let received = received.unwrap();
        assert_eq!(received.source, "test");
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let event = Event::new("test", Priority::Normal, EventKind::Keepalive);
        bus.publish(event).unwrap();

        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();

        assert_eq!(r1.id, r2.id);
    }

    #[tokio::test]
    async fn test_server_queue() {
        let (bus, mut server_rx) = EventBus::new(64, 64);
        let _sub = bus.subscribe();

        let event = Event::new("test", Priority::Normal, EventKind::Keepalive);
        bus.publish_to_server(event).await.unwrap();

        let server_event = server_rx.recv().await.unwrap();
        assert_eq!(server_event.source, "test");
    }

    #[test]
    fn test_subscriber_count() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        assert_eq!(bus.subscriber_count(), 0);

        let _rx1 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        let _rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
    }
}
