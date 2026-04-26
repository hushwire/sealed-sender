use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use sealed_sender::{
    IdentityKey, Recipient, ReplayFilter, SenderIdentity, SigningKeyId, TrustRoot,
    issue_certificate, seal_message, unseal_with_replay_check,
};

fn main() {
    let issuer_key = SigningKey::generate(&mut OsRng);
    let signing_key_id = SigningKeyId::new(1);
    let trust_root = TrustRoot::new(signing_key_id, issuer_key.verifying_key());

    let alice_secret = StaticSecret::random_from_rng(OsRng);
    let alice_pub = IdentityKey::from(PublicKey::from(&alice_secret));
    let alice_identity = SenderIdentity {
        id: Recipient::from_bytes_copy(b"alice"),
        identity_key: alice_pub,
    };
    let alice_cert = issue_certificate(
        &issuer_key,
        signing_key_id,
        &alice_identity,
        DateTime::<Utc>::MAX_UTC,
    )
    .expect("certificate issuance failed");

    let bob_secret = StaticSecret::random_from_rng(OsRng);
    let bob_pub = IdentityKey::from(PublicKey::from(&bob_secret));
    let bob_id = Recipient::from_bytes_copy(b"bob");

    // Alice sends two messages with different sequence numbers
    let msg1 = seal_message(&alice_secret, &alice_cert, &bob_id, 1, &bob_pub, b"first")
        .expect("seal failed");
    let msg2 = seal_message(&alice_secret, &alice_cert, &bob_id, 2, &bob_pub, b"second")
        .expect("seal failed");

    // Bob maintains a replay filter across messages
    let mut replay_filter = ReplayFilter::new();
    let now = Utc::now();

    let (cert, seq, inner) =
        unseal_with_replay_check(&bob_secret, &trust_root, now, &msg1, &mut replay_filter)
            .expect("unseal failed");
    println!(
        "Message {}: {:?} from {:?}",
        seq,
        std::str::from_utf8(&inner).unwrap(),
        cert.sender_id
    );

    let (cert, seq, inner) =
        unseal_with_replay_check(&bob_secret, &trust_root, now, &msg2, &mut replay_filter)
            .expect("unseal failed");
    println!(
        "Message {}: {:?} from {:?}",
        seq,
        std::str::from_utf8(&inner).unwrap(),
        cert.sender_id
    );

    // Replaying msg1 is rejected
    let result = unseal_with_replay_check::<Recipient>(
        &bob_secret,
        &trust_root,
        now,
        &msg1,
        &mut replay_filter,
    );
    match result {
        Err(sealed_sender::Error::Replay) => println!("Replay of message 1 rejected (expected)"),
        other => panic!("Expected Replay error, got: {:?}", other),
    }
}
