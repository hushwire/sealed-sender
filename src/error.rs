use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid key material")]
    InvalidKey,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("certificate expired")]
    CertificateExpired,

    #[error("unknown server key ID")]
    UnknownServerKey,

    #[error("identity key mismatch")]
    IdentityKeyMismatch,

    #[error("AEAD seal failed")]
    SealFailed,

    #[error("AEAD open failed")]
    UnsealFailed,

    #[error("serialization failed")]
    Serialization,

    #[error("unknown version: {0}")]
    UnknownVersion(u8),

    #[error("message too short")]
    MessageTooShort,
}
