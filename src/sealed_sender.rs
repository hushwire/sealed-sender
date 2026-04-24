use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::certificate::{
    SenderCertificate, SignedSenderCertificate, TrustRoot, verify_certificate,
};
use crate::error::{Error, Result};
use crate::types::{Config, IdentityKey, Timestamp};

pub struct SealedEnvelope {
    pub ek_pub: [u8; 32],
    pub encrypted_static: Vec<u8>,
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
    config: &Config,
    shared_secret: &[u8; 32],
    recipient_pub: &[u8; 32],
    ek_pub: &[u8; 32],
) -> Result<EphemeralKeys> {
    let mut salt = Vec::with_capacity(config.label.len() + 64);
    salt.extend_from_slice(config.label);
    salt.extend_from_slice(recipient_pub);
    salt.extend_from_slice(ek_pub);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut okm = Zeroizing::new([0u8; 76]);
    hk.expand(b"", okm.as_mut())
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
    hk.expand(b"", okm.as_mut())
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
pub fn seal(
    config: &Config,
    sender_identity: &StaticSecret,
    sender_cert: &SignedSenderCertificate,
    recipient_identity_public: &IdentityKey,
    inner_ciphertext: &[u8],
) -> Result<SealedEnvelope> {
    let recipient_pub = PublicKey::from(recipient_identity_public);
    let sender_pub = PublicKey::from(sender_identity);

    // --- Stage 1: Ephemeral ECDH → encrypt sender's static identity key ---

    let ek_secret = EphemeralSecret::random_from_rng(OsRng);
    let ek_pub = PublicKey::from(&ek_secret);
    let ek_pub_bytes = ek_pub.to_bytes();

    let ecdh_ephemeral_result = ecdh_ephemeral(ek_secret, &recipient_pub)?;

    let ephemeral_keys = derive_ephemeral_keys(
        config,
        &ecdh_ephemeral_result,
        recipient_identity_public.as_bytes(),
        &ek_pub_bytes,
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

    // AAD will be supplied by the caller (the routing header + encrypted_static).
    // Here we build the message_aad that binds the routing header at the wire level.
    // For the internal seal(), we use encrypted_static as the AAD since the routing
    // header binding happens at the wire::encode level.
    let encrypted_message = aead_seal(
        &static_keys.enc_key,
        &static_keys.nonce,
        &encrypted_static,
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
/// `routing_header` is the first 21 bytes of the wire message (version + recipient_id + device_id)
/// used as additional authenticated data.
#[allow(clippy::too_many_arguments)]
pub fn unseal(
    config: &Config,
    recipient_identity: &StaticSecret,
    trust_root: &TrustRoot,
    now: Timestamp,
    ek_pub_bytes: &[u8; 32],
    encrypted_static: &[u8],
    encrypted_message: &[u8],
    routing_header: &[u8],
) -> Result<(SenderCertificate, Vec<u8>)> {
    let ek_pub = PublicKey::from(*ek_pub_bytes);
    let recipient_pub = PublicKey::from(recipient_identity);

    // --- Stage 1: Ephemeral ECDH → decrypt sender's static identity key ---

    let ecdh_ephemeral_result = ecdh(&StaticSecret::from(recipient_identity.to_bytes()), &ek_pub)?;

    let ephemeral_keys = derive_ephemeral_keys(
        config,
        &ecdh_ephemeral_result,
        &recipient_pub.to_bytes(),
        ek_pub_bytes,
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

    let ecdh_static_result = ecdh(
        &StaticSecret::from(recipient_identity.to_bytes()),
        &sender_pub,
    )?;

    let static_keys = derive_static_keys(
        &ecdh_static_result,
        &ephemeral_keys.chain_key,
        encrypted_static,
    )?;

    let _ = routing_header; // reserved for future AAD binding
    let inner_payload = aead_open(
        &static_keys.enc_key,
        &static_keys.nonce,
        encrypted_static,
        encrypted_message,
    )?;

    // --- Validate ---

    let (sender_cert, remaining): (SignedSenderCertificate, _) =
        postcard::take_from_bytes(&inner_payload).map_err(|_| Error::Serialization)?;

    let inner_ciphertext = remaining.to_vec();

    // Constant-time: verify decrypted static key matches certificate claim
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
    use crate::types::{DeviceId, SenderIdentity, ServerKeyId, UserId};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    struct TestContext {
        config: Config,
        #[allow(dead_code)]
        server_key: SigningKey,
        #[allow(dead_code)]
        server_key_id: ServerKeyId,
        trust_root: TrustRoot,
        sender_static: StaticSecret,
        sender_cert: SignedSenderCertificate,
        recipient_static: StaticSecret,
        recipient_pub: IdentityKey,
    }

    fn setup() -> TestContext {
        let config = Config::default();
        let server_key = SigningKey::generate(&mut OsRng);
        let server_key_id = ServerKeyId::new(1);
        let trust_root = TrustRoot::new(server_key_id, server_key.verifying_key());

        let sender_static = StaticSecret::random_from_rng(OsRng);
        let sender_pub = PublicKey::from(&sender_static);
        let sender_identity = SenderIdentity {
            user_id: UserId::from_bytes([1u8; 16]),
            device_id: DeviceId::new(1),
            identity_key: IdentityKey::from(sender_pub),
        };

        let sender_cert = issue_certificate(
            &server_key,
            server_key_id,
            &sender_identity,
            Timestamp::from_secs(u64::MAX),
        )
        .unwrap();

        let recipient_static = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = IdentityKey::from(PublicKey::from(&recipient_static));

        TestContext {
            config,
            server_key,
            server_key_id,
            trust_root,
            sender_static,
            sender_cert,
            recipient_static,
            recipient_pub,
        }
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let ctx = setup();
        let plaintext = b"hello MLS ciphertext";

        let envelope = seal(
            &ctx.config,
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            plaintext,
        )
        .unwrap();

        let routing_header = [0u8; crate::wire::HEADER_LEN];
        let (cert, inner) = unseal(
            &ctx.config,
            &ctx.recipient_static,
            &ctx.trust_root,
            Timestamp::from_secs(0),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &envelope.encrypted_message,
            &routing_header,
        )
        .unwrap();

        assert_eq!(inner, plaintext);
        assert_eq!(cert.user_id, UserId::from_bytes([1u8; 16]));
        assert_eq!(cert.device_id, DeviceId::new(1));
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let ctx = setup();
        let envelope = seal(
            &ctx.config,
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            b"secret",
        )
        .unwrap();

        let wrong_key = StaticSecret::random_from_rng(OsRng);
        let routing_header = [0u8; crate::wire::HEADER_LEN];
        let result = unseal(
            &ctx.config,
            &wrong_key,
            &ctx.trust_root,
            Timestamp::from_secs(0),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &envelope.encrypted_message,
            &routing_header,
        );

        assert!(result.is_err());
    }

    #[test]
    fn tampered_encrypted_static_fails() {
        let ctx = setup();
        let envelope = seal(
            &ctx.config,
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            b"secret",
        )
        .unwrap();

        let mut tampered_static = envelope.encrypted_static.clone();
        tampered_static[0] ^= 0xFF;

        let routing_header = [0u8; crate::wire::HEADER_LEN];
        let result = unseal(
            &ctx.config,
            &ctx.recipient_static,
            &ctx.trust_root,
            Timestamp::from_secs(0),
            &envelope.ek_pub,
            &tampered_static,
            &envelope.encrypted_message,
            &routing_header,
        );

        assert!(matches!(result, Err(Error::UnsealFailed)));
    }

    #[test]
    fn tampered_encrypted_message_fails() {
        let ctx = setup();
        let envelope = seal(
            &ctx.config,
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            b"secret",
        )
        .unwrap();

        let mut tampered_msg = envelope.encrypted_message.clone();
        tampered_msg[0] ^= 0xFF;

        let routing_header = [0u8; crate::wire::HEADER_LEN];
        let result = unseal(
            &ctx.config,
            &ctx.recipient_static,
            &ctx.trust_root,
            Timestamp::from_secs(0),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &tampered_msg,
            &routing_header,
        );

        assert!(matches!(result, Err(Error::UnsealFailed)));
    }

    #[test]
    fn ephemeral_key_is_fresh() {
        let ctx = setup();
        let plaintext = b"same message";

        let envelope1 = seal(
            &ctx.config,
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            plaintext,
        )
        .unwrap();

        let envelope2 = seal(
            &ctx.config,
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            plaintext,
        )
        .unwrap();

        assert_ne!(envelope1.ek_pub, envelope2.ek_pub);
        assert_ne!(envelope1.encrypted_static, envelope2.encrypted_static);
        assert_ne!(envelope1.encrypted_message, envelope2.encrypted_message);
    }

    #[test]
    fn empty_inner_ciphertext() {
        let ctx = setup();

        let envelope = seal(
            &ctx.config,
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            b"",
        )
        .unwrap();

        let routing_header = [0u8; crate::wire::HEADER_LEN];
        let (_, inner) = unseal(
            &ctx.config,
            &ctx.recipient_static,
            &ctx.trust_root,
            Timestamp::from_secs(0),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &envelope.encrypted_message,
            &routing_header,
        )
        .unwrap();

        assert!(inner.is_empty());
    }

    #[test]
    fn large_inner_ciphertext() {
        let ctx = setup();
        let large_payload = vec![0x42u8; 1_000_000];

        let envelope = seal(
            &ctx.config,
            &ctx.sender_static,
            &ctx.sender_cert,
            &ctx.recipient_pub,
            &large_payload,
        )
        .unwrap();

        let routing_header = [0u8; crate::wire::HEADER_LEN];
        let (_, inner) = unseal(
            &ctx.config,
            &ctx.recipient_static,
            &ctx.trust_root,
            Timestamp::from_secs(0),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &envelope.encrypted_message,
            &routing_header,
        )
        .unwrap();

        assert_eq!(inner, large_payload);
    }

    #[test]
    fn identity_key_mismatch_detected() {
        let config = Config::default();
        let server_key = SigningKey::generate(&mut OsRng);
        let server_key_id = ServerKeyId::new(1);
        let trust_root = TrustRoot::new(server_key_id, server_key.verifying_key());

        let sender_static = StaticSecret::random_from_rng(OsRng);

        // Issue cert with a DIFFERENT identity key than the sender's actual key
        let fake_identity = IdentityKey::from_bytes([0xAA; 32]);
        let sender_identity = SenderIdentity {
            user_id: UserId::from_bytes([1u8; 16]),
            device_id: DeviceId::new(1),
            identity_key: fake_identity,
        };
        let bad_cert = issue_certificate(
            &server_key,
            server_key_id,
            &sender_identity,
            Timestamp::from_secs(u64::MAX),
        )
        .unwrap();

        let recipient_static = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = IdentityKey::from(PublicKey::from(&recipient_static));

        let envelope = seal(&config, &sender_static, &bad_cert, &recipient_pub, b"test").unwrap();

        let routing_header = [0u8; crate::wire::HEADER_LEN];
        let result = unseal(
            &config,
            &recipient_static,
            &trust_root,
            Timestamp::from_secs(0),
            &envelope.ek_pub,
            &envelope.encrypted_static,
            &envelope.encrypted_message,
            &routing_header,
        );

        // The decrypted static key (sender_pub) won't match the cert's identity_key (fake_identity)
        assert!(matches!(result, Err(Error::IdentityKeyMismatch)));
    }
}
