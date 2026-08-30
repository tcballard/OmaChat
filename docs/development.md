# Development contract

OmaChat 0.0.1 is a Rust workspace containing eight crates. The toolchain is
locked to Rust 1.98.0 in `rust-toolchain.toml`; the workspace manifest declares
Rust 1.98 as its minimum supported Rust version (MSRV). Changing either value
requires a pull request that updates both together and demonstrates the full
check suite on the proposed toolchain.

## Workspace

| Crate | Kind | Initial responsibility |
|---|---|---|
| `omachat-proto` | library | Protocol codec boundary and shared compatibility metadata |
| `omachat-crypto` | library | Protocol cryptography boundary |
| `omachat-mesh` | library | BlueZ mesh transport boundary |
| `omachat-nostr` | library | Nostr relay transport boundary |
| `omachat-store` | library | Sealed persistence boundary |
| `omachatd` | binary | Headless daemon |
| `omachat-tui` | binary package | `omachat` terminal client |
| `omachat-ctl` | binary | Control and scripting client |

The scaffold intentionally contains no wire constants, packet layouts,
cryptographic schedules, relay URLs, or runtime behavior. Those values remain
blocked on the extraction and conformance work named in the build backlog.

## Local checks

Run the same contract enforced in CI from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo build --workspace --bins --locked
./scripts/check-version-contract.sh
```

CI additionally runs `cargo-audit` through the RustSec audit action and
`cargo-deny` with the repository's minimal advisory, ban, license, and source
policy. Dependencies must be recorded in `Cargo.lock`; wildcard requirements,
yanked crates, unknown registries, and unknown Git sources are denied.
