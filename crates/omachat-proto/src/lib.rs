pub mod hosted;
pub mod ipc;
#[must_use]
pub fn version_line(binary: &str) -> String {
    format!(
        "{binary} {} (ipc={})",
        env!("CARGO_PKG_VERSION"),
        ipc::VERSION
    )
}
