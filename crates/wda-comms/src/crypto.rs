//! AES-256-CBC encryption for Wazuh protocol messages.
//!
//! The Wazuh protocol encrypts messages using AES-256-CBC with a key
//! derived from the agent's pre-shared key.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use ring::rand::SecureRandom;
use sha2::{Digest, Sha256};
use tracing::debug;

type Aes256CbcEnc = Encryptor<aes::Aes256>;
type Aes256CbcDec = Decryptor<aes::Aes256>;

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

/// Wazuh protocol cipher using AES-256-CBC.
///
/// Keys are derived from the agent's pre-shared key using SHA-256.
pub struct WazuhCipher {
    /// AES-256 key (32 bytes, derived from agent key).
    key: [u8; 32],
}

impl WazuhCipher {
    /// Create a new cipher from an agent key string.
    ///
    /// The key is derived by taking the SHA-256 hash of the agent key.
    pub fn new(agent_key: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(agent_key.as_bytes());
        let key: [u8; 32] = hasher.finalize().into();

        Self { key }
    }

    /// Encrypt a plaintext message.
    ///
    /// Returns the IV prepended to the ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Generate a random IV
        let iv: [u8; 16] = generate_iv();

        // Encrypt with PKCS7 padding using in-place buffer
        let cipher = Aes256CbcEnc::new(&self.key.into(), &iv.into());

        // Allocate buffer: plaintext + up to 16 bytes padding
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let ciphertext = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .map_err(|_| CryptoError::EncryptionFailed("padding error".to_string()))?;

        // Prepend IV to ciphertext
        let mut result = Vec::with_capacity(16 + ciphertext.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(ciphertext);

        debug!(
            plaintext_len = plaintext.len(),
            ciphertext_len = result.len(),
            "encrypted message"
        );

        Ok(result)
    }

    /// Decrypt a ciphertext message.
    ///
    /// Expects the IV prepended to the ciphertext (first 16 bytes).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 17 {
            return Err(CryptoError::DecryptionFailed(
                "data too short (need at least IV + 1 block)".to_string(),
            ));
        }

        let (iv_bytes, ciphertext) = data.split_at(16);
        let iv: [u8; 16] = iv_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed("invalid IV length".to_string()))?;

        let cipher = Aes256CbcDec::new(&self.key.into(), &iv.into());

        // Decrypt in-place
        let mut buf = ciphertext.to_vec();
        let plaintext = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| CryptoError::DecryptionFailed("unpadding error".to_string()))?;

        let decrypted = plaintext.to_vec();

        debug!(
            ciphertext_len = data.len(),
            plaintext_len = decrypted.len(),
            "decrypted message"
        );

        Ok(decrypted)
    }
}

/// Generate a random 16-byte IV using ring's secure RNG.
fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut iv)
        .expect("system RNG failed");
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = WazuhCipher::new("test-agent-key-12345");
        let plaintext = b"Hello, Wazuh server!";

        let encrypted = cipher.encrypt(plaintext).unwrap();
        assert_ne!(&encrypted[16..], plaintext); // ciphertext differs from plaintext

        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_different_keys_fail() {
        let cipher1 = WazuhCipher::new("key-one");
        let cipher2 = WazuhCipher::new("key-two");

        let encrypted = cipher1.encrypt(b"secret data").unwrap();
        let result = cipher2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let cipher = WazuhCipher::new("test-key");
        let encrypted = cipher.encrypt(b"").unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_large_message() {
        let cipher = WazuhCipher::new("test-key");
        let plaintext = vec![0x42u8; 65536];
        let encrypted = cipher.encrypt(&plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_too_short() {
        let cipher = WazuhCipher::new("test-key");
        let result = cipher.decrypt(&[0u8; 10]);
        assert!(result.is_err());
    }
}
