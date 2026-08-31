# Development contract

OmaChat 0.0.1 is a Rust workspace containing nine crates. The toolchain is
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

The workspace now contains protocol, cryptographic, storage, daemon, IPC,
CLI/TUI, and packaging implementation. Hardware, live-peer, target-host, and
soak evidence remain blocked on the conformance work named in the build backlog;
code presence alone never closes those gates.

## Local checks

Run the same contract enforced in CI from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo build --workspace --bins --locked
./scripts/check-version-contract.sh
sh ./scripts/check-packaging.sh
```

CI additionally runs `cargo-audit` through the RustSec audit action and
`cargo-deny` with the repository's minimal advisory, ban, license, and source
policy. Dependencies must be recorded in `Cargo.lock`; wildcard requirements,
yanked crates, unknown registries, and unknown Git sources are denied.

The dependency policy permits 0BSD, Apache-2.0, MIT, Unicode-3.0, ISC, and the
two- and three-clause BSD licenses. The BSD/ISC additions cover the pinned
BlueR and Rustls probe stacks; they do not weaken the Android clean-room rule or
allow copyleft source into OmaChat.
