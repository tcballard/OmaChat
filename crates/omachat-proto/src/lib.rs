//! Hosted wire protocol and bounded local IPC.
pub mod hosted;
pub mod ipc;
#[must_use]
pub fn version_line(binary: &str) -> String {
    format!(
        "{binary} {} (hosted-v1; ipc={})",
        env!("CARGO_PKG_VERSION"),
        ipc::VERSION
    )
}
