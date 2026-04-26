# sealed-sender

Sealed sender for MLS. Provides sender anonymity by wrapping encrypted
ciphertext in a two-stage ECIES envelope. The relay sees only the
recipient; the recipient recovers the sender's verified identity.

## How it works

The sender wraps an already-encrypted inner ciphertext (e.g. an MLS application
message) in a two-layer ECIES envelope:

1. **Stage 1 (ephemeral ECDH):** A fresh X25519 keypair encrypts the sender's
   static identity key using ChaCha20-Poly1305.
2. **Stage 2 (static ECDH):** The sender's long-term key performs a second ECDH
   with the recipient, chained from stage 1 via HKDF. This encrypts the sender
   certificate and inner ciphertext.

The relay routes the message using the plaintext routing header
(recipient ID) but cannot see who sent it. The recipient decrypts both layers,
verifies the sender's Ed25519-signed certificate, and recovers the inner
ciphertext.

## Generic identity model

The library is generic over recipient/sender identifiers via the `RecipientId`
trait. Your identity type might be a UUID, a (user, device) pair, a string
handle, or anything serializable. Implement `RecipientId` for your type, or
use the provided `Recipient` opaque byte wrapper.

## Usage

```rust,ignore
use sealed_sender::{
    seal_message, unseal_with_replay_check, issue_certificate,
    Recipient, IdentityKey, SigningKeyId,
    SenderIdentity, TrustRoot, ReplayFilter,
};

// Issuer creates a sender certificate
let cert = issue_certificate(
    &signing_key, signing_key_id, &sender_identity, expires_at,
).unwrap();

// Sender seals a message
let wire_bytes = seal_message(
    &sender_secret, &cert,
    &recipient_id, message_sequence,
    &recipient_public_key, &mls_ciphertext,
).unwrap();

// Recipient unseals with replay protection
let mut replay_filter = ReplayFilter::new();
let (sender_cert, seq, inner) = unseal_with_replay_check(
    &recipient_secret, &trust_root,
    chrono::Utc::now(), &wire_bytes, &mut replay_filter,
).unwrap();
```

## Feature flags

| Flag | Default | Description |
|------|---------|-------------|
| `uuid` | off | `From` conversions between `Recipient` and `uuid::Uuid` |
| `mls-rs` | off | `TryFrom` conversions between `IdentityKey` and `mls_rs_core::crypto::HpkePublicKey` |

## Minimum Rust version

1.85 (edition 2024).

## Security

This library has not yet been audited. Do not use in production until an
external security audit is complete.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
