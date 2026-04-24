use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use sealed_sender::{
    Config, DeviceId, IdentityKey, SenderIdentity, ServerKeyId, Timestamp, TrustRoot, UserId,
    issue_certificate, seal_message, unseal_message, verify_certificate,
};

fn setup_server() -> (SigningKey, ServerKeyId, TrustRoot) {
    let server_key = SigningKey::generate(&mut OsRng);
    let server_key_id = ServerKeyId::new(1);
    let trust_root = TrustRoot::new(server_key_id, server_key.verifying_key());
    (server_key, server_key_id, trust_root)
}

fn setup_user(user_id: [u8; 16], device_id: u32) -> (StaticSecret, IdentityKey, SenderIdentity) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = IdentityKey::from(PublicKey::from(&secret));
    let identity = SenderIdentity {
        user_id: UserId::from_bytes(user_id),
        device_id: DeviceId::new(device_id),
        identity_key: public,
    };
    (secret, public, identity)
}

#[test]
fn end_to_end_seal_unseal() {
    let config = Config::default();
    let (server_key, server_key_id, trust_root) = setup_server();
    let (alice_secret, _, alice_identity) = setup_user([0xAA; 16], 1);
    let (bob_secret, bob_pub, _) = setup_user([0xBB; 16], 1);

    let alice_cert = issue_certificate(
        &server_key,
        server_key_id,
        &alice_identity,
        Timestamp::from_secs(u64::MAX),
    )
    .unwrap();

    let mls_ciphertext = b"MLS application message ciphertext";

    let wire_bytes = seal_message(
        &config,
        &alice_secret,
        &alice_cert,
        UserId::from_bytes([0xBB; 16]),
        DeviceId::new(1),
        &bob_pub,
        mls_ciphertext,
    )
    .unwrap();

    let (sender_cert, inner) = unseal_message(
        &config,
        &bob_secret,
        &trust_root,
        Timestamp::from_secs(0),
        &wire_bytes,
    )
    .unwrap();

    assert_eq!(inner, mls_ciphertext);
    assert_eq!(sender_cert.user_id, UserId::from_bytes([0xAA; 16]));
    assert_eq!(sender_cert.device_id, DeviceId::new(1));
    assert_eq!(sender_cert.identity_key, alice_identity.identity_key);
}

#[test]
fn multi_device_same_message() {
    let config = Config::default();
    let (server_key, server_key_id, trust_root) = setup_server();
    let (alice_secret, _, alice_identity) = setup_user([0xAA; 16], 1);

    let alice_cert = issue_certificate(
        &server_key,
        server_key_id,
        &alice_identity,
        Timestamp::from_secs(u64::MAX),
    )
    .unwrap();

    let bob_device_1 = StaticSecret::random_from_rng(OsRng);
    let bob_device_1_pub = IdentityKey::from(PublicKey::from(&bob_device_1));

    let bob_device_2 = StaticSecret::random_from_rng(OsRng);
    let bob_device_2_pub = IdentityKey::from(PublicKey::from(&bob_device_2));

    let mls_ciphertext = b"shared MLS ciphertext";

    let wire_1 = seal_message(
        &config,
        &alice_secret,
        &alice_cert,
        UserId::from_bytes([0xBB; 16]),
        DeviceId::new(1),
        &bob_device_1_pub,
        mls_ciphertext,
    )
    .unwrap();

    let wire_2 = seal_message(
        &config,
        &alice_secret,
        &alice_cert,
        UserId::from_bytes([0xBB; 16]),
        DeviceId::new(2),
        &bob_device_2_pub,
        mls_ciphertext,
    )
    .unwrap();

    // Different sealed envelopes (different ephemeral keys)
    assert_ne!(wire_1, wire_2);

    // Both unseal to the same inner ciphertext
    let (cert_1, inner_1) = unseal_message(
        &config,
        &bob_device_1,
        &trust_root,
        Timestamp::from_secs(0),
        &wire_1,
    )
    .unwrap();

    let (cert_2, inner_2) = unseal_message(
        &config,
        &bob_device_2,
        &trust_root,
        Timestamp::from_secs(0),
        &wire_2,
    )
    .unwrap();

    assert_eq!(inner_1, mls_ciphertext);
    assert_eq!(inner_2, mls_ciphertext);
    assert_eq!(cert_1.user_id, cert_2.user_id);
}

#[test]
fn wrong_recipient_cannot_unseal() {
    let config = Config::default();
    let (server_key, server_key_id, trust_root) = setup_server();
    let (alice_secret, _, alice_identity) = setup_user([0xAA; 16], 1);
    let (_, bob_pub, _) = setup_user([0xBB; 16], 1);

    let alice_cert = issue_certificate(
        &server_key,
        server_key_id,
        &alice_identity,
        Timestamp::from_secs(u64::MAX),
    )
    .unwrap();

    let wire_bytes = seal_message(
        &config,
        &alice_secret,
        &alice_cert,
        UserId::from_bytes([0xBB; 16]),
        DeviceId::new(1),
        &bob_pub,
        b"secret",
    )
    .unwrap();

    let eve_secret = StaticSecret::random_from_rng(OsRng);
    let result = unseal_message(
        &config,
        &eve_secret,
        &trust_root,
        Timestamp::from_secs(0),
        &wire_bytes,
    );

    assert!(result.is_err());
}

#[test]
fn expired_cert_rejected_on_unseal() {
    let config = Config::default();
    let (server_key, server_key_id, trust_root) = setup_server();
    let (alice_secret, _, alice_identity) = setup_user([0xAA; 16], 1);
    let (bob_secret, bob_pub, _) = setup_user([0xBB; 16], 1);

    let alice_cert = issue_certificate(
        &server_key,
        server_key_id,
        &alice_identity,
        Timestamp::from_secs(1000),
    )
    .unwrap();

    let wire_bytes = seal_message(
        &config,
        &alice_secret,
        &alice_cert,
        UserId::from_bytes([0xBB; 16]),
        DeviceId::new(1),
        &bob_pub,
        b"secret",
    )
    .unwrap();

    // Verify at time > expires_at
    let result = unseal_message(
        &config,
        &bob_secret,
        &trust_root,
        Timestamp::from_secs(2000),
        &wire_bytes,
    );

    assert!(result.is_err());
}

#[test]
fn custom_config_label() {
    let config = Config {
        label: b"HushwireSealedSender-v1",
    };
    let (server_key, server_key_id, trust_root) = setup_server();
    let (alice_secret, _, alice_identity) = setup_user([0xAA; 16], 1);
    let (bob_secret, bob_pub, _) = setup_user([0xBB; 16], 1);

    let alice_cert = issue_certificate(
        &server_key,
        server_key_id,
        &alice_identity,
        Timestamp::from_secs(u64::MAX),
    )
    .unwrap();

    let wire_bytes = seal_message(
        &config,
        &alice_secret,
        &alice_cert,
        UserId::from_bytes([0xBB; 16]),
        DeviceId::new(1),
        &bob_pub,
        b"custom label test",
    )
    .unwrap();

    let (_, inner) = unseal_message(
        &config,
        &bob_secret,
        &trust_root,
        Timestamp::from_secs(0),
        &wire_bytes,
    )
    .unwrap();
    assert_eq!(inner, b"custom label test");

    // Different label cannot unseal
    let wrong_config = Config::default();
    let result = unseal_message(
        &wrong_config,
        &bob_secret,
        &trust_root,
        Timestamp::from_secs(0),
        &wire_bytes,
    );
    assert!(result.is_err());
}

#[test]
fn verify_certificate_standalone() {
    let (server_key, server_key_id, trust_root) = setup_server();
    let (_, _, alice_identity) = setup_user([0xAA; 16], 1);

    let cert = issue_certificate(
        &server_key,
        server_key_id,
        &alice_identity,
        Timestamp::from_secs(5000),
    )
    .unwrap();

    verify_certificate(&trust_root, &cert, Timestamp::from_secs(4999)).unwrap();
    assert!(verify_certificate(&trust_root, &cert, Timestamp::from_secs(5000)).is_err());
}
