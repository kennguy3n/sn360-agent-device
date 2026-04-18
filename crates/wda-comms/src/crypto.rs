//! Wazuh protocol encryption.
//!
//! Supports Blowfish-CBC (default for Wazuh ≤ 4.x) and AES-256-CBC
//! (when the manager is configured with `<crypto_method>aes</crypto_method>`).
//!
//! Key derivation follows the Wazuh protocol: the full agent key material
//! (`{id} {name} {ip} {key}`) is split in half; each half is MD5-hashed;
//! the two hex digests are concatenated to form the cipher key.
//!
//! Message framing (applied before encryption):
//!   `{5-char random}{global_counter}:{local_counter}{sep}{message}`
//! where `sep` is `:` (uncompressed) or `!` (compressed).

use std::sync::atomic::{AtomicU32, Ordering};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::{Digest as Md5Digest, Md5};
use ring::rand::SecureRandom;
use tracing::debug;

use crate::blowfish_wazuh::{bf_cbc_decrypt, bf_cbc_encrypt, Blowfish};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Errors from crypto operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("invalid key length")]
    InvalidKeyLength,
}

/// Which block cipher to use for the Wazuh secure channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CryptoMethod {
    /// Blowfish-CBC with static zero IV (Wazuh default).
    #[default]
    Blowfish,
    /// AES-256-CBC with random IV prepended to ciphertext.
    Aes,
}

/// Wazuh protocol cipher.
///
/// Handles key derivation, message framing, and encryption/decryption
/// compatible with a real Wazuh 4.x manager.
pub struct WazuhCipher {
    method: CryptoMethod,
    /// AES-256 key (first 32 bytes of the key material, used only in AES mode).
    aes_key: [u8; 32],
    /// Blowfish cipher instance (precomputed, used only in Blowfish mode).
    blowfish: Blowfish,
    /// Message counter (local), incremented per message.
    local_counter: AtomicU32,
}

impl WazuhCipher {
    /// Create a new cipher from the four agent key fields.
    ///
    /// Wazuh derives the encryption key by:
    /// 1. Concatenating `"{id} {name} {ip} {key}"` (space-separated).
    /// 2. Splitting the string in half.
    /// 3. MD5-hashing each half.
    /// 4. Concatenating the two hex digests → 64-char ASCII string.
    pub fn new(id: &str, name: &str, ip: &str, key: &str, method: CryptoMethod) -> Self {
        let full = format!("{} {} {} {}", id, name, ip, key);
        let half = full.len() / 2;
        let (first, second) = full.as_bytes().split_at(half);

        let md5_first = hex_md5(first);
        let md5_second = hex_md5(second);

        let mut key_material = Vec::with_capacity(64);
        key_material.extend_from_slice(md5_first.as_bytes());
        key_material.extend_from_slice(md5_second.as_bytes());

        debug!(
            key_len = key_material.len(),
            method = ?method,
            "derived Wazuh cipher key"
        );

        let blowfish = Blowfish::new(&key_material);

        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&key_material[..32]);

        Self {
            method,
            aes_key,
            blowfish,
            local_counter: AtomicU32::new(0),
        }
    }

    /// Encrypt a plaintext message with Wazuh framing.
    ///
    /// Prepends the standard Wazuh message header
    /// (`{5-random}{global}:{local}:{msg}`) then encrypts with the
    /// configured cipher.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let framed = self.add_framing(plaintext, false);

        let ciphertext = match self.method {
            CryptoMethod::Blowfish => bf_cbc_encrypt(&self.blowfish, &framed),
            CryptoMethod::Aes => self.aes_encrypt(&framed)?,
        };

        debug!(
            plaintext_len = plaintext.len(),
            framed_len = framed.len(),
            ciphertext_len = ciphertext.len(),
            method = ?self.method,
            "encrypted message"
        );

        Ok(ciphertext)
    }

    /// Decrypt a ciphertext message and strip the Wazuh framing.
    ///
    /// Returns only the inner message payload (after the header).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let decrypted = match self.method {
            CryptoMethod::Blowfish => bf_cbc_decrypt(&self.blowfish, data),
            CryptoMethod::Aes => self.aes_decrypt(data)?,
        };

        let payload = self.strip_framing(&decrypted)?;

        debug!(
            ciphertext_len = data.len(),
            payload_len = payload.len(),
            method = ?self.method,
            "decrypted message"
        );

        Ok(payload)
    }

    /// Build the framed plaintext: `{5-random}{0}:{local}{sep}{message}`
    fn add_framing(&self, message: &[u8], compressed: bool) -> Vec<u8> {
        let random_id = random_alphanum_5();
        let local = self.local_counter.fetch_add(1, Ordering::Relaxed);
        let sep = if compressed { '!' } else { ':' };

        let header = format!(
            "{}0:{}{}",
            std::str::from_utf8(&random_id).unwrap_or("AAAAA"),
            local,
            sep,
        );

        let mut buf = Vec::with_capacity(header.len() + message.len());
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(message);
        buf
    }

    /// Strip the Wazuh framing header and return the inner message.
    ///
    /// Expected format: `{5-random}{global}:{local}{sep}{message}`
    fn strip_framing(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Strip trailing null bytes (zero-padding from Blowfish).
        let data = strip_trailing_nulls(data);

        if data.len() < 7 {
            return Err(CryptoError::DecryptionFailed(
                "decrypted data too short for Wazuh framing".into(),
            ));
        }

        // Skip the 5-char random prefix.
        let rest = &data[5..];

        // Find the separator after the counters: the second ':' or first '!'.
        // Format: "{global}:{local}:{msg}" or "{global}:{local}!{compressed}"
        let sep_pos = find_message_separator(rest).ok_or_else(|| {
            CryptoError::DecryptionFailed("cannot find message separator in framing".into())
        })?;

        Ok(rest[sep_pos + 1..].to_vec())
    }

    /// AES-256-CBC encrypt (random IV prepended to ciphertext).
    fn aes_encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let iv = generate_iv_16();
        let cipher = Aes256CbcEnc::new(&self.aes_key.into(), &iv.into());

        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let ct = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .map_err(|_| CryptoError::EncryptionFailed("AES padding error".into()))?;

        let mut result = Vec::with_capacity(16 + ct.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(ct);
        Ok(result)
    }

    /// AES-256-CBC decrypt (IV is the first 16 bytes).
    fn aes_decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 32 {
            return Err(CryptoError::DecryptionFailed(
                "data too short (need IV + 1 block)".into(),
            ));
        }
        let (iv_bytes, ct) = data.split_at(16);
        let iv: [u8; 16] = iv_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed("invalid IV length".into()))?;

        let cipher = Aes256CbcDec::new(&self.aes_key.into(), &iv.into());
        let mut buf = ct.to_vec();
        let pt = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| CryptoError::DecryptionFailed("AES unpadding error".into()))?;
        Ok(pt.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute MD5 and return the lowercase hex digest (32 chars).
fn hex_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Generate 5 random alphanumeric ASCII characters (Wazuh random ID).
fn random_alphanum_5() -> [u8; 5] {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = [0u8; 5];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .expect("system RNG failed");
    for b in &mut buf {
        *b = CHARSET[(*b as usize) % CHARSET.len()];
    }
    buf
}

/// Generate a random 16-byte IV for AES-CBC.
fn generate_iv_16() -> [u8; 16] {
    let mut iv = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut iv)
        .expect("system RNG failed");
    iv
}

/// Strip trailing null bytes.
fn strip_trailing_nulls(data: &[u8]) -> &[u8] {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &data[..end]
}

/// Find the position of the message separator after the counter fields.
///
/// The counter portion is `{global}:{local}`, so we look for the second
/// `:` or the first `!` after the first `:`.
fn find_message_separator(data: &[u8]) -> Option<usize> {
    let first_colon = data.iter().position(|&b| b == b':')?;
    // After the first colon, look for ':' (uncompressed) or '!' (compressed).
    for (i, &b) in data[first_colon + 1..].iter().enumerate() {
        if b == b':' || b == b'!' {
            return Some(first_colon + 1 + i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let cipher = WazuhCipher::new(
            "001",
            "agent1",
            "any",
            "secretkey123",
            CryptoMethod::Blowfish,
        );
        // Key material should be 64 printable hex characters.
        assert_eq!(cipher.aes_key.len(), 32);
    }

    #[test]
    fn test_blowfish_roundtrip() {
        let cipher = WazuhCipher::new(
            "001",
            "myhost",
            "any",
            "abc123def456",
            CryptoMethod::Blowfish,
        );
        let plaintext = b"#!-agent keepalive";

        let encrypted = cipher.encrypt(plaintext).unwrap();
        assert!(!encrypted.is_empty());

        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_roundtrip() {
        let cipher = WazuhCipher::new("002", "myhost", "any", "key456", CryptoMethod::Aes);
        let plaintext = b"d:{\"type\":\"event\",\"data\":{}}";

        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_keys_fail_blowfish() {
        let cipher1 = WazuhCipher::new("001", "host1", "any", "key1", CryptoMethod::Blowfish);
        let cipher2 = WazuhCipher::new("002", "host2", "any", "key2", CryptoMethod::Blowfish);

        let encrypted = cipher1.encrypt(b"secret data").unwrap();
        // Decryption may produce garbage; framing parse should fail.
        let result = cipher2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keys_fail_aes() {
        let cipher1 = WazuhCipher::new("001", "host1", "any", "key1", CryptoMethod::Aes);
        let cipher2 = WazuhCipher::new("002", "host2", "any", "key2", CryptoMethod::Aes);

        let encrypted = cipher1.encrypt(b"secret data").unwrap();
        let result = cipher2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_large_message_blowfish() {
        let cipher = WazuhCipher::new("001", "host", "any", "k", CryptoMethod::Blowfish);
        let plaintext = vec![0x42u8; 65536];
        let encrypted = cipher.encrypt(&plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_message_aes() {
        let cipher = WazuhCipher::new("001", "host", "any", "k", CryptoMethod::Aes);
        let plaintext = vec![0x42u8; 65536];
        let encrypted = cipher.encrypt(&plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_framing_counter_increments() {
        let cipher = WazuhCipher::new("001", "host", "any", "k", CryptoMethod::Blowfish);

        let framed1 = cipher.add_framing(b"msg1", false);
        let framed2 = cipher.add_framing(b"msg2", false);

        let s1 = String::from_utf8_lossy(&framed1);
        let s2 = String::from_utf8_lossy(&framed2);
        assert!(
            s1.contains(":0:"),
            "first message should have counter 0: {s1}"
        );
        assert!(
            s2.contains(":1:"),
            "second message should have counter 1: {s2}"
        );
    }

    #[test]
    fn test_strip_trailing_nulls() {
        assert_eq!(strip_trailing_nulls(b"hello\0\0\0"), b"hello");
        assert_eq!(strip_trailing_nulls(b"hello"), b"hello");
        assert_eq!(strip_trailing_nulls(b"\0\0"), b"" as &[u8]);
    }
}
