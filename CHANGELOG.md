# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - 2026-04-25

Initial release.

### Added
- Two-stage ECIES sealed sender protocol (X25519 + ChaCha20-Poly1305 + HKDF-SHA256)
- Generic `RecipientId` trait for pluggable identity types
- `Recipient` opaque byte wrapper as the default identity type
- Ed25519-signed sender certificates with expiry and key rotation via `TrustRoot`
- Sliding-window replay protection (RFC 6479, 64-packet window, per-sender)
- Compact wire format with version byte and variable-length recipient IDs
- Optional `uuid` feature for `Recipient` <-> `Uuid` conversions
- Optional `mls-rs` feature for `IdentityKey` <-> `HpkePublicKey` conversions
- GitHub Actions CI testing all feature combinations
