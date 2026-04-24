use thiserror::Error;

/// Alias for `Result<T, sealed_sender::Error>`.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by sealed sender operations.
#[derive(Debug, Error)]
pub enum Error {
    /// The key material is invalid (wrong length, all-zero DH result, etc.).
    #[error("invalid key material")]
    InvalidKey,

    /// Ed25519 signature verification failed on a sender certificate.
    #[error("invalid signature")]
    InvalidSignature,

    /// The sender certificate has expired.
    #[error("certificate expired")]
    CertificateExpired,

    /// The `ServerKeyId` in the certificate does not match any key in the [`TrustRoot`](crate::TrustRoot).
    #[error("unknown server key ID")]
    UnknownServerKey,

    /// The ECIES-decrypted static key does not match the certificate's claimed identity key.
    #[error("identity key mismatch")]
    IdentityKeyMismatch,

    /// ChaCha20-Poly1305 encryption failed.
    #[error("AEAD seal failed")]
    SealFailed,

    /// ChaCha20-Poly1305 decryption failed (wrong key, tampered ciphertext, or wrong AAD).
    #[error("AEAD open failed")]
    UnsealFailed,

    /// Postcard serialization or deserialization failed.
    #[error("serialization failed")]
    Serialization,

    /// The wire format version byte is not recognized.
    #[error("unknown version: {0}")]
    UnknownVersion(u8),

    /// The wire-format message is shorter than the minimum valid size.
    #[error("message too short")]
    MessageTooShort,
}
