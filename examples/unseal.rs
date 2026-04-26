use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use sealed_sender::{
    IdentityKey, Recipient, SenderIdentity, SigningKeyId, TrustRoot, issue_certificate,
    seal_message, unseal_message,
};

fn main() {
    // Set up a signing authority (could be a server, peer, group admin, etc.)
    let issuer_key = SigningKey::generate(&mut OsRng);
    let signing_key_id = SigningKeyId::new(1);
    let trust_root = TrustRoot::new(signing_key_id, issuer_key.verifying_key());

    // Alice: the sender
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

    // Bob: the recipient
    let bob_secret = StaticSecret::random_from_rng(OsRng);
    let bob_pub = IdentityKey::from(PublicKey::from(&bob_secret));
    let bob_id = Recipient::from_bytes_copy(b"bob");

    // Alice seals a message for Bob
    let plaintext = b"hello from alice";
    let wire_bytes = seal_message(&alice_secret, &alice_cert, &bob_id, 1, &bob_pub, plaintext)
        .expect("seal failed");

    println!(
        "Sealed {} bytes into {} wire bytes",
        plaintext.len(),
        wire_bytes.len()
    );

    // Bob unseals it
    let (sender_cert, seq, inner) =
        unseal_message::<Recipient>(&bob_secret, &trust_root, Utc::now(), &wire_bytes)
            .expect("unseal failed");

    println!("Sender: {:?}, seq: {}", sender_cert.sender_id, seq);
    println!("Decrypted: {:?}", std::str::from_utf8(&inner).unwrap());
}
