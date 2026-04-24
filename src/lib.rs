#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod certificate;
pub mod error;
pub mod sealed_sender;
pub mod types;
pub mod wire;

pub use certificate::{
    SenderCertificate, SignedSenderCertificate, TrustRoot, issue_certificate, verify_certificate,
};
pub use error::{Error, Result};
pub use types::{Config, DeviceId, IdentityKey, SenderIdentity, ServerKeyId, Timestamp, UserId};

use x25519_dalek::StaticSecret;

/// Seal an inner ciphertext for delivery to a specific recipient device.
///
/// Produces wire-format bytes that hide the sender's identity from the relay
/// server. The recipient can unseal the message and recover the sender's
/// verified identity.
#[must_use = "sealed message bytes must be sent to the recipient"]
pub fn seal_message(
    config: &Config,
    sender_identity: &StaticSecret,
    sender_cert: &SignedSenderCertificate,
    recipient_id: UserId,
    recipient_device_id: DeviceId,
    recipient_identity_public: &IdentityKey,
    inner_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let envelope = sealed_sender::seal(
        config,
        sender_identity,
        sender_cert,
        recipient_identity_public,
        inner_ciphertext,
    )?;

    Ok(wire::encode(recipient_id, recipient_device_id, &envelope))
}

/// Unseal a wire-format sealed sender message.
///
/// Returns the verified sender certificate and the inner ciphertext.
/// Validates the certificate chain, expiry, and constant-time identity key
/// match between the ECIES-decrypted static key and the certificate claim.
pub fn unseal_message(
    config: &Config,
    recipient_identity: &StaticSecret,
    trust_root: &TrustRoot,
    now: Timestamp,
    wire_bytes: &[u8],
) -> Result<(SenderCertificate, Vec<u8>)> {
    let msg = wire::decode(wire_bytes)?;

    sealed_sender::unseal(
        config,
        recipient_identity,
        trust_root,
        now,
        &msg.ek_pub,
        msg.encrypted_static,
        msg.encrypted_message,
        &wire_bytes[..wire::HEADER_LEN],
    )
}
