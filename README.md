# sealed-sender

Sealed sender for MLS. Provides server-side sender anonymity by wrapping
encrypted ciphertext in a two-stage ECIES envelope (mirroring Signal's sealed
sender protocol). The server sees only the recipient; the recipient recovers
the sender's verified identity.

## Security

This library has not yet been audited. Do not use in production until an
external security audit is complete.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
