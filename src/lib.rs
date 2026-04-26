#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod certificate;
pub mod error;
pub mod replay;
pub mod sealed_sender;
pub mod types;
pub mod wire;

pub use certificate::{
    SenderCertificate, SignedSenderCertificate, TrustRoot, issue_certificate, verify_certificate,
};
pub use error::{Error, Result};
pub use replay::ReplayFilter;
pub use types::{IdentityKey, Recipient, RecipientId, SenderIdentity, ServerKeyId};

use chrono::{DateTime, Utc};
use x25519_dalek::StaticSecret;

/// Seal an inner ciphertext for delivery to a specific recipient.
///
/// Produces wire-format bytes that hide the sender's identity from the relay
/// server. The recipient can unseal the message and recover the sender's
/// verified identity.
#[must_use = "sealed message bytes must be sent to the recipient"]
pub fn seal_message<R: RecipientId>(
    sender_identity: &StaticSecret,
    sender_cert: &SignedSenderCertificate<R>,
    recipient_id: &R,
    message_sequence: u64,
    recipient_identity_public: &IdentityKey,
    inner_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let routing_header = wire::build_header(recipient_id, message_sequence);

    let envelope = sealed_sender::seal(
        sender_identity,
        sender_cert,
        recipient_identity_public,
        inner_ciphertext,
        &routing_header,
    )?;

    Ok(wire::encode_with_header(&routing_header, &envelope))
}

/// Unseal a wire-format sealed sender message.
///
/// Returns the verified sender certificate, the message sequence number,
/// and the inner ciphertext. Validates the certificate chain, expiry, and
/// constant-time identity key match between the ECIES-decrypted static key
/// and the certificate claim.
///
/// # Replay protection
///
/// This function does **not** check for replayed messages. Callers must
/// either use [`unseal_with_replay_check`] (recommended) or pass the
/// returned sequence number to [`ReplayFilter::check`] after calling this
/// function. Skipping replay checking allows an attacker to re-deliver
/// previously captured messages.
pub fn unseal_message<R: RecipientId>(
    recipient_identity: &StaticSecret,
    trust_root: &TrustRoot,
    now: DateTime<Utc>,
    wire_bytes: &[u8],
) -> Result<(SenderCertificate<R>, u64, Vec<u8>)> {
    let msg: wire::DecodedMessage<'_, R> = wire::decode(wire_bytes)?;

    let (cert, inner) = sealed_sender::unseal(
        recipient_identity,
        trust_root,
        now,
        &msg.ek_pub,
        msg.encrypted_static,
        msg.encrypted_message,
        &wire_bytes[..msg.header_len],
    )?;

    Ok((cert, msg.message_sequence, inner))
}

/// Unseal a wire-format sealed sender message with replay protection.
///
/// Combines [`unseal_message`] with a [`ReplayFilter`] check. Returns
/// [`Error::Replay`] if the message sequence number has already been seen
/// for this sender.
pub fn unseal_with_replay_check<R: RecipientId>(
    recipient_identity: &StaticSecret,
    trust_root: &TrustRoot,
    now: DateTime<Utc>,
    wire_bytes: &[u8],
    replay_filter: &mut ReplayFilter<R>,
) -> Result<(SenderCertificate<R>, u64, Vec<u8>)> {
    let (cert, seq, inner) = unseal_message::<R>(recipient_identity, trust_root, now, wire_bytes)?;

    if !replay_filter.check(cert.sender_id.clone(), seq) {
        return Err(Error::Replay);
    }

    Ok((cert, seq, inner))
}
