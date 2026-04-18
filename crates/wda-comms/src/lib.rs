//! Communication layer for the Wazuh Desktop Agent.
//!
//! Implements the Wazuh server protocol (v4.x compatible) with Blowfish-CBC
//! or AES-256-CBC encryption, TCP/UDP transport, automatic reconnection,
//! and message batching.

pub mod blowfish_wazuh;
pub mod connection;
pub mod crypto;
pub mod enrollment;
pub mod keepalive;
pub mod protocol;
