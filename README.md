# sealed-sender

Sealed sender for MLS. Provides server-side sender anonymity by wrapping
encrypted ciphertext in a two-stage ECIES envelope (mirroring Signal's sealed
sender protocol). The server sees only the recipient; the recipient recovers
the sender's verified identity.

## How it works

The sender wraps an already-encrypted inner ciphertext (e.g. an MLS application
message) in a two-layer ECIES envelope:

1. **Stage 1 (ephemeral ECDH):** A fresh X25519 keypair encrypts the sender's
   static identity key using ChaCha20-Poly1305.
2. **Stage 2 (static ECDH):** The sender's long-term key performs a second ECDH
   with the recipient, chained from stage 1 via HKDF. This encrypts the sender
   certificate and inner ciphertext.

The server routes the message using the plaintext routing header
(recipient ID + device ID) but cannot see who sent it. The recipient decrypts
both layers, verifies the sender's Ed25519-signed certificate, and recovers
the inner ciphertext.

## Usage

```rust,ignore
use sealed_sender::{
    seal_message, unseal_message, issue_certificate,
    Config, UserId, DeviceId, IdentityKey, ServerKeyId,
    SenderIdentity, TrustRoot,
};

// Server issues a sender certificate
let cert = issue_certificate(
    &server_signing_key, server_key_id, &sender_identity, expires_at,
).unwrap();

// Sender seals a message
let wire_bytes = seal_message(
    &Config::default(), &sender_secret, &cert,
    recipient_id, device_id, &recipient_public_key,
    &mls_ciphertext,
).unwrap();

// Recipient unseals
let (sender_cert, inner) = unseal_message(
    &Config::default(), &recipient_secret, &trust_root,
    chrono::Utc::now(), &wire_bytes,
).unwrap();
```

## Feature flags

| Flag | Default | Description |
|------|---------|-------------|
| `uuid` | off | `From` conversions between `UserId` and `uuid::Uuid` |
| `mls-rs` | off | `TryFrom` conversions between `IdentityKey` and `mls_rs_core::crypto::HpkePublicKey` |

## Security

This library has not yet been audited. Do not use in production until an
external security audit is complete.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
