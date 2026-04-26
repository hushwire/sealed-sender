use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::error::Result;

#[cfg(feature = "uuid")]
use crate::error::Error;

/// Trait for recipient (and sender) identifiers in the sealed sender protocol.
///
/// Implementors define how their identity type is serialized into the wire
/// format routing header. The library is agnostic about what an identity
/// represents: it could be a single UUID, a (user, device) pair, a string
/// handle, or anything else.
///
/// The wire format stores the identity as a length-prefixed byte sequence,
/// so implementations may return any byte length from [`to_bytes`](RecipientId::to_bytes).
pub trait RecipientId:
    Clone + Eq + std::hash::Hash + Serialize + DeserializeOwned + std::fmt::Debug
{
    fn to_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

/// A variable-length opaque recipient identifier.
///
/// This is the default [`RecipientId`] implementation provided by the library.
/// It stores arbitrary bytes, making it compatible with UUIDs, composite
/// (user + device) identifiers, or any other format.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Recipient(Vec<u8>);

impl Recipient {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_bytes_copy(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl RecipientId for Recipient {
    fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}

#[cfg(feature = "uuid")]
impl From<uuid::Uuid> for Recipient {
    fn from(id: uuid::Uuid) -> Self {
        Self(id.as_bytes().to_vec())
    }
}

#[cfg(feature = "uuid")]
impl TryFrom<Recipient> for uuid::Uuid {
    type Error = Error;
    fn try_from(r: Recipient) -> Result<Self> {
        let bytes: [u8; 16] = r.0.try_into().map_err(|_| Error::InvalidRecipientId)?;
        Ok(uuid::Uuid::from_bytes(bytes))
    }
}

/// An X25519 public key used as a long-term identity key.
///
/// Equality comparison is constant-time via [`subtle::ConstantTimeEq`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct IdentityKey([u8; 32]);

impl IdentityKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ConstantTimeEq for IdentityKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for IdentityKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for IdentityKey {}

impl From<x25519_dalek::PublicKey> for IdentityKey {
    fn from(key: x25519_dalek::PublicKey) -> Self {
        Self(key.to_bytes())
    }
}

impl From<&IdentityKey> for x25519_dalek::PublicKey {
    fn from(key: &IdentityKey) -> Self {
        x25519_dalek::PublicKey::from(key.0)
    }
}

#[cfg(feature = "mls-rs")]
impl TryFrom<&mls_rs_core::crypto::HpkePublicKey> for IdentityKey {
    type Error = crate::error::Error;

    fn try_from(key: &mls_rs_core::crypto::HpkePublicKey) -> crate::error::Result<Self> {
        let bytes: &[u8] = key.as_ref();
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| crate::error::Error::InvalidKey)?;
        Ok(Self(arr))
    }
}

#[cfg(feature = "mls-rs")]
impl From<IdentityKey> for mls_rs_core::crypto::HpkePublicKey {
    fn from(key: IdentityKey) -> Self {
        mls_rs_core::crypto::HpkePublicKey::new(key.0.to_vec())
    }
}

/// Identifies which server Ed25519 signing key issued a certificate.
///
/// Supports key rotation: the [`TrustRoot`](crate::TrustRoot) maps `ServerKeyId` to public keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServerKeyId(u32);

impl ServerKeyId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// The sender's identity fields needed to issue a [`SenderCertificate`](crate::SenderCertificate).
pub struct SenderIdentity<R: RecipientId> {
    pub id: R,
    pub identity_key: IdentityKey,
}
