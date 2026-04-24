use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId([u8; 16]);

impl UserId {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(u32);

impl DeviceId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

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
impl From<&mls_rs_core::crypto::HpkePublicKey> for IdentityKey {
    fn from(key: &mls_rs_core::crypto::HpkePublicKey) -> Self {
        let bytes: &[u8] = key.as_ref();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Self(arr)
    }
}

#[cfg(feature = "mls-rs")]
impl From<IdentityKey> for mls_rs_core::crypto::HpkePublicKey {
    fn from(key: IdentityKey) -> Self {
        mls_rs_core::crypto::HpkePublicKey::new(key.0.to_vec())
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    pub fn as_secs(&self) -> u64 {
        self.0
    }

    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();
        Self(secs)
    }
}

#[cfg(feature = "uuid")]
impl From<uuid::Uuid> for UserId {
    fn from(id: uuid::Uuid) -> Self {
        Self(*id.as_bytes())
    }
}

#[cfg(feature = "uuid")]
impl From<UserId> for uuid::Uuid {
    fn from(id: UserId) -> Self {
        uuid::Uuid::from_bytes(id.0)
    }
}

pub struct SenderIdentity {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub identity_key: IdentityKey,
}

pub struct Config {
    pub label: &'static [u8],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            label: b"SealedSender",
        }
    }
}
