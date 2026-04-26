use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use chrono::{DateTime, Utc};

use crate::certificate::{
    SenderCertificate, SignedSenderCertificate, TrustRoot, verify_certificate,
};
use crate::error::{Error, Result};
use crate::types::{IdentityKey, RecipientId};

/// The output of [`seal`]: an ECIES envelope ready for wire encoding.
///
/// Contains the ephemeral public key and two ciphertext layers
/// (encrypted sender identity key + encrypted message payload).
pub struct SealedEnvelope {
    /// Ephemeral X25519 public key (fresh per message).
    pub ek_pub: [u8; 32],
    /// Stage 1 ciphertext: sender's static identity key (32 bytes + 16-byte Poly1305 tag).
    pub encrypted_static: Vec<u8>,
    /// Stage 2 ciphertext: sender certificate + inner ciphertext (variable + 16-byte tag).
    pub encrypted_message: Vec<u8>,
}

struct EphemeralKeys {
    chain_key: Zeroizing<[u8; 32]>,
    enc_key: Zeroizing<[u8; 32]>,
    nonce: [u8; 12],
}

struct StaticKeys {
    enc_key: Zeroizing<[u8; 32]>,
    nonce: [u8; 12],
}

fn derive_ephemeral_keys(
    shared_secret: &[u8; 32],
    ek_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> Result<EphemeralKeys> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ek_pub);
    salt[32..].copy_from_slice(recipient_pub);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut okm = Zeroizing::new([0u8; 76]);
    hk.expand(b"HushwireSealedSender-v1", okm.as_mut())
        .map_err(|_| Error::InvalidKey)?;

    let mut chain_key = Zeroizing::new([0u8; 32]);
    let mut enc_key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 12];

    chain_key.copy_from_slice(&okm[..32]);
    enc_key.copy_from_slice(&okm[32..64]);
    nonce.copy_from_slice(&okm[64..76]);

    Ok(EphemeralKeys {
        chain_key,
        enc_key,
        nonce,
    })
}

fn derive_static_keys(
    shared_secret: &[u8; 32],
    chain_key: &[u8; 32],
    encrypted_static: &[u8],
) -> Result<StaticKeys> {
    let mut salt = Vec::with_capacity(32 + encrypted_static.len());
    salt.extend_from_slice(chain_key);
    salt.extend_from_slice(encrypted_static);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut okm = Zeroizing::new([0u8; 44]);
    hk.expand(b"HushwireSealedSender-v1-static", okm.as_mut())
        .map_err(|_| Error::InvalidKey)?;

    let mut enc_key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 12];

    enc_key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..44]);

    Ok(StaticKeys { enc_key, nonce })
}

fn ecdh(secret: &StaticSecret, public: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
    let shared = secret.diffie_hellman(public);
    let bytes = shared.to_bytes();
    if bytes.ct_eq(&[0u8; 32]).into() {
        return Err(Error::InvalidKey);
    }
    Ok(Zeroizing::new(bytes))
}

fn ecdh_ephemeral(secret: EphemeralSecret, public: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
    let shared = secret.diffie_hellman(public);
    let bytes = shared.to_bytes();
    if bytes.ct_eq(&[0u8; 32]).into() {
        return Err(Error::InvalidKey);
    }
    Ok(Zeroizing::new(bytes))
}

fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::SealFailed)
}

fn aead_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::UnsealFailed)
}

/// Seal an inner ciphertext using the two-stage ECIES protocol.
///
/// `routing_header` is the wire format header bound into the stage 2 AEAD
/// as additional authenticated data.
pub fn seal<R: RecipientId>(
    sender_identity: &StaticSecret,
    sender_cert: &SignedSenderCertificate<R>,
    recipient_identity_public: &IdentityKey,
    inner_ciphertext: &[u8],
    routing_header: &[u8],
) -> Result<SealedEnvelope> {
    let recipient_pub = PublicKey::from(recipient_identity_public);
    let sender_pub = PublicKey::from(sender_identity);

    // --- Stage 1: Ephemeral ECDH → encrypt sender's static identity key ---

    let ek_secret = EphemeralSecret::random_from_rng(OsRng);
    let ek_pub = PublicKey::from(&ek_secret);
    let ek_pub_bytes = ek_pub.to_bytes();

    let ecdh_ephemeral_result = ecdh_ephemeral(ek_secret, &recipient_pub)?;

    let ephemeral_keys = derive_ephemeral_keys(
        &ecdh_ephemeral_result,
        &ek_pub_bytes,
        recipient_identity_public.as_bytes(),
    )?;

    let encrypted_static = aead_seal(
        &ephemeral_keys.enc_key,
        &ephemeral_keys.nonce,
        &ek_pub_bytes,
        &sender_pub.to_bytes(),
    )?;

    // --- Stage 2: Static ECDH → encrypt message ---

    let ecdh_static_result = ecdh(sender_identity, &recipient_pub)?;

    let static_keys = derive_static_keys(
        &ecdh_static_result,
        &ephemeral_keys.chain_key,
        &encrypted_static,
    )?;

    let cert_bytes = postcard::to_allocvec(sender_cert).map_err(|_| Error::Serialization)?;
    let mut inner_payload = Vec::with_capacity(cert_bytes.len() + inner_ciphertext.len());
    inner_payload.extend_from_slice(&cert_bytes);
    inner_payload.extend_from_slice(inner_ciphertext);

    let mut message_aad = Vec::with_capacity(routing_header.len() + encrypted_static.len());
    message_aad.extend_from_slice(routing_header);
    message_aad.extend_from_slice(&encrypted_static);

    let encrypted_message = aead_seal(
        &static_keys.enc_key,
        &static_keys.nonce,
        &message_aad,
        &inner_payload,
    )?;

    Ok(SealedEnvelope {
        ek_pub: ek_pub_bytes,
        encrypted_static,
        encrypted_message,
    })
}

/// Unseal a sealed sender message using the two-stage ECIES protocol.
///
/// Returns the verified [`SenderCertificate`] and the inner ciphertext.
///
/// **Replay protection is NOT performed by this function.** Callers must
/// either use [`crate::unseal_with_replay_check`] (recommended) or manually
/// pass the returned sequence number to [`crate::ReplayFilter::check`] after
/// calling [`crate::unseal_message`].
#[allow(clippy::too_many_arguments)]
pub fn unseal<R: RecipientId>(
    recipient_identity: &StaticSecret,
    trust_root: &TrustRoot,
    now: DateTime<Utc>,
    ek_pub_bytes: &[u8; 32],
    encrypted_static: &[u8],
    encrypted_message: &[u8],
    routing_header: &[u8],
) -> Result<(SenderCertificate<R>, Vec<u8>)> {
    let ek_pub = PublicKey::from(*ek_pub_bytes);
    let recipient_pub = PublicKey::from(recipient_identity);

    // --- Stage 1: Ephemeral ECDH → decrypt sender's static identity key ---

    let ecdh_ephemeral_result = ecdh(recipient_identity, &ek_pub)?;

    let ephemeral_keys = derive_ephemeral_keys(
        &ecdh_ephemeral_result,
        ek_pub_bytes,
        &recipient_pub.to_bytes(),
    )?;

    let sender_pub_bytes = aead_open(
        &ephemeral_keys.enc_key,
        &ephemeral_keys.nonce,
        ek_pub_bytes,
        encrypted_static,
    )?;

    if sender_pub_bytes.len() != 32 {
        return Err(Error::InvalidKey);
    }

    let mut sender_pub_arr = [0u8; 32];
    sender_pub_arr.copy_from_slice(&sender_pub_bytes);
    let sender_identity_key = IdentityKey::from_bytes(sender_pub_arr);
    let sender_pub = PublicKey::from(sender_pub_arr);

    // --- Stage 2: Static ECDH → decrypt message ---

    let ecdh_static_result = ecdh(recipient_identity, &sender_pub)?;

    let static_keys = derive_static_keys(
        &ecdh_static_result,
        &ephemeral_keys.chain_key,
        encrypted_static,
    )?;

    let mut message_aad = Vec::with_capacity(routing_header.len() + encrypted_static.len());
    message_aad.extend_from_slice(routing_header);
    message_aad.extend_from_slice(encrypted_static);

    let inner_payload = aead_open(
        &static_keys.enc_key,
        &static_keys.nonce,
        &message_aad,
        encrypted_message,
    )?;

    // --- Validate ---

    let (sender_cert, remaining): (SignedSenderCertificate<R>, _) =
        postcard::take_from_bytes(&inner_payload).map_err(|_| Error::Serialization)?;

    let inner_ciphertext = remaining.to_vec();

    if !bool::from(
        sender_cert
            .certificate
            .identity_key
            .ct_eq(&sender_identity_key),
    ) {
        return Err(Error::IdentityKeyMismatch);
    }

    verify_certificate(trust_root, &sender_cert, now)?;

    Ok((sender_cert.certificate, inner_ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::issue_certificate;
    use crate::types::{Recipient, SenderIdentity, ServerKeyId};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    struct TestContext {
        #[allow(dead_code)]
        server_key: SigningKey,
        #[allow(dead_code)]
        server_key_id: ServerKeyId,
        trust_root: TrustRoot,
        sender_static: StaticSecret,
        sender_cert: SignedSenderCertificate<Recipient>,
        recipient_static: StaticSecret,
        recipient_pub: IdentityKey,
    }

    fn setup() -> TestContext {
        let server_key = SigningKey::generate(&mut OsRng);
        let server_key_id = ServerKeyId::new(1);
        let trust_root = TrustRoot::new(server_key_id, server_key.verifying_key());

        let sender_static = StaticSecret::random_from_rng(OsRng);
        let sender_pub = PublicKey::from(&sender_static);
        let sender_identity = SenderIdentity {
            id: Recipient::from_bytes_copy(&[1u8; 16]),
            identity_key: IdentityKey::from(sender_pub),
        };

        let sender_cert = issue_certificate(
            &server_key,
            server_key_id,
            &sender_identity,
            DateTime::<Utc>::MAX_UTC,
        )
        .unwrap();

        let recipient_static = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = IdentityKey::from(PublicKey::from(&recipient_static));

        TestContext {
            server_key,
            server_key_id,
            trust_root,
            sender_static,
            sender_cert,
            recipient_static,
            recipient_pub,
        }
    }

    fn dummy_header() -> Vec<u8> {
        crate::wire::build_header(&Recipient::from_bytes_copy(&[0u8; 16]), 0)
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let ctx = setup();
        let plaintext = b"hello MLS ciphertext";
        let header = dummy_header();

        let envelope = seal(
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            plaintext,
            &header,
        )
        .unwrap();
        let (cert, inner): (SenderCertificate<Recipient>, _) = unseal(
            &ctx.recipient_static,
            &ctx.trust_root,
            Utc.timestamp_opt(0, 0).unwrap(),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &envelope.encrypted_message,
            &header,
        )
        .unwrap();

        assert_eq!(inner, plaintext);
        assert_eq!(cert.sender_id, Recipient::from_bytes_copy(&[1u8; 16]));
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let ctx = setup();
        let header = dummy_header();
        let envelope = seal(
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            b"secret",
            &header,
        )
        .unwrap();

        let wrong_key = StaticSecret::random_from_rng(OsRng);
        let result: Result<(SenderCertificate<Recipient>, _)> = unseal(
            &wrong_key,
            &ctx.trust_root,
            Utc.timestamp_opt(0, 0).unwrap(),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &envelope.encrypted_message,
            &header,
        );

        assert!(result.is_err());
    }

    #[test]
    fn tampered_encrypted_static_fails() {
        let ctx = setup();
        let header = dummy_header();
        let envelope = seal(
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            b"secret",
            &header,
        )
        .unwrap();

        let mut tampered_static = envelope.encrypted_static.clone();
        tampered_static[0] ^= 0xFF;

        let result: Result<(SenderCertificate<Recipient>, _)> = unseal(
            &ctx.recipient_static,
            &ctx.trust_root,
            Utc.timestamp_opt(0, 0).unwrap(),
            &envelope.ek_pub,
            &tampered_static,
            &envelope.encrypted_message,
            &header,
        );

        assert!(matches!(result, Err(Error::UnsealFailed)));
    }

    #[test]
    fn tampered_encrypted_message_fails() {
        let ctx = setup();
        let header = dummy_header();
        let envelope = seal(
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            b"secret",
            &header,
        )
        .unwrap();

        let mut tampered_msg = envelope.encrypted_message.clone();
        tampered_msg[0] ^= 0xFF;

        let result: Result<(SenderCertificate<Recipient>, _)> = unseal(
            &ctx.recipient_static,
            &ctx.trust_root,
            Utc.timestamp_opt(0, 0).unwrap(),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &tampered_msg,
            &header,
        );

        assert!(matches!(result, Err(Error::UnsealFailed)));
    }

    #[test]
    fn ephemeral_key_is_fresh() {
        let ctx = setup();
        let plaintext = b"same message";
        let header = dummy_header();

        let e1 = seal(
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            plaintext,
            &header,
        )
        .unwrap();

        let e2 = seal(
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            plaintext,
            &header,
        )
        .unwrap();

        assert_ne!(e1.ek_pub, e2.ek_pub);
        assert_ne!(e1.encrypted_static, e2.encrypted_static);
        assert_ne!(e1.encrypted_message, e2.encrypted_message);
    }

    #[test]
    fn empty_inner_ciphertext() {
        let ctx = setup();
        let header = dummy_header();

        let envelope = seal(
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            b"",
            &header,
        )
        .unwrap();
        let (_, inner): (SenderCertificate<Recipient>, _) = unseal(
            &ctx.recipient_static,
            &ctx.trust_root,
            Utc.timestamp_opt(0, 0).unwrap(),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &envelope.encrypted_message,
            &header,
        )
        .unwrap();

        assert!(inner.is_empty());
    }

    #[test]
    fn large_inner_ciphertext() {
        let ctx = setup();
        let large_payload = vec![0x42u8; 1_000_000];
        let header = dummy_header();

        let envelope = seal(
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            &large_payload,
            &header,
        )
        .unwrap();
        let (_, inner): (SenderCertificate<Recipient>, _) = unseal(
            &ctx.recipient_static,
            &ctx.trust_root,
            Utc.timestamp_opt(0, 0).unwrap(),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &envelope.encrypted_message,
            &header,
        )
        .unwrap();

        assert_eq!(inner, large_payload);
    }

    #[test]
    fn identity_key_mismatch_detected() {
        let server_key = SigningKey::generate(&mut OsRng);
        let server_key_id = ServerKeyId::new(1);
        let trust_root = TrustRoot::new(server_key_id, server_key.verifying_key());

        let sender_static = StaticSecret::random_from_rng(OsRng);

        let fake_identity = IdentityKey::from_bytes([0xAA; 32]);
        let sender_identity = SenderIdentity {
            id: Recipient::from_bytes_copy(&[1u8; 16]),
            identity_key: fake_identity,
        };
        let bad_cert = issue_certificate(
            &server_key,
            server_key_id,
            &sender_identity,
            DateTime::<Utc>::MAX_UTC,
        )
        .unwrap();

        let recipient_static = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = IdentityKey::from(PublicKey::from(&recipient_static));

        let header = dummy_header();
        let envelope = seal(
            &sender_static,
            &bad_cert,
            &recipient_pub,
            b"test",
            &header,
        )
        .unwrap();
        let result: Result<(SenderCertificate<Recipient>, _)> = unseal(
            &recipient_static,
            &trust_root,
            Utc.timestamp_opt(0, 0).unwrap(),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &envelope.encrypted_message,
            &header,
        );

        assert!(matches!(result, Err(Error::IdentityKeyMismatch)));
    }
}
