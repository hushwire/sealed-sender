use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use sealed_sender::{
    IdentityKey, Recipient, ReplayFilter, SenderIdentity, SigningKeyId, TrustRoot,
    issue_certificate, seal_message, unseal_message, unseal_with_replay_check, verify_certificate,
};

fn setup_issuer() -> (SigningKey, SigningKeyId, TrustRoot) {
    let issuer_key = SigningKey::generate(&mut OsRng);
    let signing_key_id = SigningKeyId::new(1);
    let trust_root = TrustRoot::new(signing_key_id, issuer_key.verifying_key());
    (issuer_key, signing_key_id, trust_root)
}

fn setup_user(id: &[u8]) -> (StaticSecret, IdentityKey, SenderIdentity<Recipient>) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = IdentityKey::from(PublicKey::from(&secret));
    let identity = SenderIdentity {
        id: Recipient::from_bytes_copy(id),
        identity_key: public,
    };
    (secret, public, identity)
}

#[test]
fn end_to_end_seal_unseal() {
    let (issuer_key, signing_key_id, trust_root) = setup_issuer();
    let (alice_secret, _, alice_identity) = setup_user(&[0xAA; 16]);
    let (bob_secret, bob_pub, _) = setup_user(&[0xBB; 16]);

    let alice_cert = issue_certificate(
        &issuer_key,
        signing_key_id,
        &alice_identity,
        DateTime::<Utc>::MAX_UTC,
    )
    .unwrap();

    let mls_ciphertext = b"MLS application message ciphertext";
    let bob_rid = Recipient::from_bytes_copy(&[0xBB; 16]);

    let wire_bytes = seal_message(
        &alice_secret,
        &alice_cert,
        &bob_rid,
        1,
        &bob_pub,
        mls_ciphertext,
    )
    .unwrap();

    let (sender_cert, seq, inner) = unseal_message::<Recipient>(
        &bob_secret,
        &trust_root,
        Utc.timestamp_opt(0, 0).unwrap(),
        &wire_bytes,
    )
    .unwrap();

    assert_eq!(inner, mls_ciphertext);
    assert_eq!(seq, 1);
    assert_eq!(sender_cert.sender_id, alice_identity.id);
    assert_eq!(sender_cert.identity_key, alice_identity.identity_key);
}

#[test]
fn multi_device_same_message() {
    let (issuer_key, signing_key_id, trust_root) = setup_issuer();
    let (alice_secret, _, alice_identity) = setup_user(&[0xAA; 16]);

    let alice_cert = issue_certificate(
        &issuer_key,
        signing_key_id,
        &alice_identity,
        DateTime::<Utc>::MAX_UTC,
    )
    .unwrap();

    let bob_device_1 = StaticSecret::random_from_rng(OsRng);
    let bob_device_1_pub = IdentityKey::from(PublicKey::from(&bob_device_1));

    let bob_device_2 = StaticSecret::random_from_rng(OsRng);
    let bob_device_2_pub = IdentityKey::from(PublicKey::from(&bob_device_2));

    let mls_ciphertext = b"shared MLS ciphertext";
    let bob_d1 = Recipient::from_bytes_copy(&[0xB1; 16]);
    let bob_d2 = Recipient::from_bytes_copy(&[0xB2; 16]);

    let wire_1 = seal_message(
        &alice_secret,
        &alice_cert,
        &bob_d1,
        1,
        &bob_device_1_pub,
        mls_ciphertext,
    )
    .unwrap();

    let wire_2 = seal_message(
        &alice_secret,
        &alice_cert,
        &bob_d2,
        1,
        &bob_device_2_pub,
        mls_ciphertext,
    )
    .unwrap();

    assert_ne!(wire_1, wire_2);

    let (cert_1, _, inner_1) = unseal_message::<Recipient>(
        &bob_device_1,
        &trust_root,
        Utc.timestamp_opt(0, 0).unwrap(),
        &wire_1,
    )
    .unwrap();

    let (cert_2, _, inner_2) = unseal_message::<Recipient>(
        &bob_device_2,
        &trust_root,
        Utc.timestamp_opt(0, 0).unwrap(),
        &wire_2,
    )
    .unwrap();

    assert_eq!(inner_1, mls_ciphertext);
    assert_eq!(inner_2, mls_ciphertext);
    assert_eq!(cert_1.sender_id, cert_2.sender_id);
}

#[test]
fn wrong_recipient_cannot_unseal() {
    let (issuer_key, signing_key_id, trust_root) = setup_issuer();
    let (alice_secret, _, alice_identity) = setup_user(&[0xAA; 16]);
    let (_, bob_pub, _) = setup_user(&[0xBB; 16]);

    let alice_cert = issue_certificate(
        &issuer_key,
        signing_key_id,
        &alice_identity,
        DateTime::<Utc>::MAX_UTC,
    )
    .unwrap();

    let bob_rid = Recipient::from_bytes_copy(&[0xBB; 16]);
    let wire_bytes =
        seal_message(&alice_secret, &alice_cert, &bob_rid, 1, &bob_pub, b"secret").unwrap();

    let eve_secret = StaticSecret::random_from_rng(OsRng);
    let result = unseal_message::<Recipient>(
        &eve_secret,
        &trust_root,
        Utc.timestamp_opt(0, 0).unwrap(),
        &wire_bytes,
    );

    assert!(result.is_err());
}

#[test]
fn expired_cert_rejected_on_unseal() {
    let (issuer_key, signing_key_id, trust_root) = setup_issuer();
    let (alice_secret, _, alice_identity) = setup_user(&[0xAA; 16]);
    let (bob_secret, bob_pub, _) = setup_user(&[0xBB; 16]);

    let alice_cert = issue_certificate(
        &issuer_key,
        signing_key_id,
        &alice_identity,
        Utc.timestamp_opt(1000, 0).unwrap(),
    )
    .unwrap();

    let bob_rid = Recipient::from_bytes_copy(&[0xBB; 16]);
    let wire_bytes =
        seal_message(&alice_secret, &alice_cert, &bob_rid, 1, &bob_pub, b"secret").unwrap();

    let result = unseal_message::<Recipient>(
        &bob_secret,
        &trust_root,
        Utc.timestamp_opt(2000, 0).unwrap(),
        &wire_bytes,
    );

    assert!(result.is_err());
}

#[test]
fn verify_certificate_standalone() {
    let (issuer_key, signing_key_id, trust_root) = setup_issuer();
    let (_, _, alice_identity) = setup_user(&[0xAA; 16]);

    let cert = issue_certificate(
        &issuer_key,
        signing_key_id,
        &alice_identity,
        Utc.timestamp_opt(5000, 0).unwrap(),
    )
    .unwrap();

    verify_certificate(&trust_root, &cert, Utc.timestamp_opt(4999, 0).unwrap()).unwrap();
    assert!(verify_certificate(&trust_root, &cert, Utc.timestamp_opt(5000, 0).unwrap()).is_err());
}

#[test]
fn end_to_end_wire_format_roundtrip() {
    let (issuer_key, signing_key_id, trust_root) = setup_issuer();
    let (alice_secret, _, alice_identity) = setup_user(&[0xAA; 16]);
    let (bob_secret, bob_pub, _) = setup_user(&[0xBB; 16]);

    let alice_cert = issue_certificate(
        &issuer_key,
        signing_key_id,
        &alice_identity,
        DateTime::<Utc>::MAX_UTC,
    )
    .unwrap();

    let inner = b"end-to-end wire format test payload";
    let seq = 42u64;
    let bob_rid = Recipient::from_bytes_copy(&[0xBB; 16]);

    let wire_bytes =
        seal_message(&alice_secret, &alice_cert, &bob_rid, seq, &bob_pub, inner).unwrap();

    assert_eq!(wire_bytes[0], 0x01); // version
    assert_eq!(&wire_bytes[1..3], &16u16.to_le_bytes()); // recipient id length
    assert_eq!(&wire_bytes[3..19], &[0xBB; 16]); // recipient bytes
    assert_eq!(
        u64::from_le_bytes(wire_bytes[19..27].try_into().unwrap()),
        42u64
    ); // message_sequence

    let (sender_cert, returned_seq, decrypted) = unseal_message::<Recipient>(
        &bob_secret,
        &trust_root,
        Utc.timestamp_opt(0, 0).unwrap(),
        &wire_bytes,
    )
    .unwrap();

    assert_eq!(decrypted, inner);
    assert_eq!(returned_seq, seq);
    assert_eq!(sender_cert.sender_id, alice_identity.id);
    assert_eq!(sender_cert.signing_key_id, signing_key_id);
}

#[test]
fn tampered_sequence_number_detected() {
    let (issuer_key, signing_key_id, trust_root) = setup_issuer();
    let (alice_secret, _, alice_identity) = setup_user(&[0xAA; 16]);
    let (bob_secret, bob_pub, _) = setup_user(&[0xBB; 16]);

    let alice_cert = issue_certificate(
        &issuer_key,
        signing_key_id,
        &alice_identity,
        DateTime::<Utc>::MAX_UTC,
    )
    .unwrap();

    let bob_rid = Recipient::from_bytes_copy(&[0xBB; 16]);
    let mut wire_bytes =
        seal_message(&alice_secret, &alice_cert, &bob_rid, 1, &bob_pub, b"secret").unwrap();

    // Tamper with the message_sequence field (starts at offset 19 for a 16-byte recipient)
    wire_bytes[19] ^= 0xFF;

    let result = unseal_message::<Recipient>(
        &bob_secret,
        &trust_root,
        Utc.timestamp_opt(0, 0).unwrap(),
        &wire_bytes,
    );

    assert!(result.is_err());
}

#[test]
fn unseal_with_replay_check_rejects_duplicate() {
    let (issuer_key, signing_key_id, trust_root) = setup_issuer();
    let (alice_secret, _, alice_identity) = setup_user(&[0xAA; 16]);
    let (bob_secret, bob_pub, _) = setup_user(&[0xBB; 16]);

    let alice_cert = issue_certificate(
        &issuer_key,
        signing_key_id,
        &alice_identity,
        DateTime::<Utc>::MAX_UTC,
    )
    .unwrap();

    let mut replay = ReplayFilter::new();
    let bob_rid = Recipient::from_bytes_copy(&[0xBB; 16]);

    let wire_bytes = seal_message(
        &alice_secret,
        &alice_cert,
        &bob_rid,
        1,
        &bob_pub,
        b"message 1",
    )
    .unwrap();

    let now = Utc.timestamp_opt(0, 0).unwrap();

    let (cert, seq, _) =
        unseal_with_replay_check(&bob_secret, &trust_root, now, &wire_bytes, &mut replay).unwrap();

    assert_eq!(seq, 1);
    assert_eq!(cert.sender_id, alice_identity.id);

    let result = unseal_with_replay_check::<Recipient>(
        &bob_secret,
        &trust_root,
        now,
        &wire_bytes,
        &mut replay,
    );
    assert!(matches!(result, Err(sealed_sender::Error::Replay)));
}

#[test]
fn variable_length_recipient_ids() {
    let (issuer_key, signing_key_id, trust_root) = setup_issuer();

    let sender_secret = StaticSecret::random_from_rng(OsRng);
    let sender_pub = IdentityKey::from(PublicKey::from(&sender_secret));
    let sender_identity = SenderIdentity {
        id: Recipient::from_bytes_copy(b"alice@example.com"),
        identity_key: sender_pub,
    };

    let alice_cert = issue_certificate(
        &issuer_key,
        signing_key_id,
        &sender_identity,
        DateTime::<Utc>::MAX_UTC,
    )
    .unwrap();

    let bob_secret = StaticSecret::random_from_rng(OsRng);
    let bob_pub = IdentityKey::from(PublicKey::from(&bob_secret));
    let bob_rid = Recipient::from_bytes_copy(b"bob@example.com");

    let wire_bytes = seal_message(
        &sender_secret,
        &alice_cert,
        &bob_rid,
        1,
        &bob_pub,
        b"hello variable-length ids",
    )
    .unwrap();

    let (cert, _, inner) = unseal_message::<Recipient>(
        &bob_secret,
        &trust_root,
        Utc.timestamp_opt(0, 0).unwrap(),
        &wire_bytes,
    )
    .unwrap();

    assert_eq!(inner, b"hello variable-length ids");
    assert_eq!(
        cert.sender_id,
        Recipient::from_bytes_copy(b"alice@example.com")
    );
}
