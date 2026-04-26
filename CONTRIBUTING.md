# Contributing

Thanks for your interest in contributing to sealed-sender.

## Bug reports

Please file bugs as GitHub issues with enough detail to reproduce the problem:
Rust version, OS, feature flags enabled, and a minimal code sample or test case
that demonstrates the issue.

## Security vulnerabilities

Please report security bugs by opening a
[draft security advisory](https://github.com/hushwire/sealed-sender/security/advisories/new)
on GitHub, not as a regular issue. This gives us a chance to prepare a fix before
public disclosure.

## Code changes

For small fixes, open a PR directly. For larger features or protocol changes, please
file an issue first so we can discuss the design before you invest significant time.

Works-in-progress PRs are welcome. Mark them as draft.

## Commit hygiene

We prefer small, focused commits that each do one thing. In particular:

- Keep formatting changes separate from functional changes.
- Keep dependency updates in their own commits.
- Do not mix refactoring with behavioral changes.

Rebase before merging to keep a linear history on `main`.

## Testing

All feature flags must be tested. Run the full matrix before submitting:

```sh
cargo test
cargo test --features mls-rs
cargo test --features uuid
cargo test --all-features
```

PRs that introduce test failures or reduce coverage are unlikely to be accepted.
New public API surface should come with tests. Changes to the cryptographic protocol
(ECIES stages, HKDF derivation, wire format) require test coverage for both the
happy path and relevant error cases.

## Code style

We use `cargo fmt` (default settings) and `cargo clippy`. Beyond that:

- **No unsafe code.** The crate uses `#![forbid(unsafe_code)]`. All cryptographic
  operations go through safe abstractions from the RustCrypto ecosystem.
- **Error handling.** Return `Result` with a specific error variant. No `unwrap()`
  or `expect()` in library code. Tests may use `unwrap()`.
- **Naming.** Prefer concise names. Expand non-obvious acronyms on first use in
  doc comments. The library is topology-agnostic, so avoid terms like "server" or
  "client" that imply a specific deployment model.
- **Imports.** Group into three blocks: `std`, external crates, `crate::` imports.
- **Documentation.** All public items need a doc comment. The crate enforces
  `#![warn(missing_docs)]`.
- **Constant-time operations.** Any comparison involving key material or secret
  data must use `subtle::ConstantTimeEq`, not `==`.
- **Key material.** Sensitive values must be wrapped in `zeroize::Zeroizing` so
  they are cleared from memory on drop.

## Design principles

- **Topology-agnostic.** The protocol does not assume client-server, peer-to-peer,
  or any other topology. Certificates are issued by "signing authorities," not
  "servers."
- **Generic identity model.** The library is parameterized over `RecipientId` so
  callers can use whatever identity type fits their system.
- **Safe defaults.** Replay protection is opt-in but prominently documented.
  Certificate expiry is mandatory.
- **Minimal public surface.** Internal modules are `pub(crate)`. The public API
  is the set of items re-exported from `lib.rs`.

## License

Contributions are accepted under the same dual license as the project:
Apache-2.0 OR MIT.
