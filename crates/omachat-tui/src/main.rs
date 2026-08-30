use std::{env, ffi::OsStr, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() == Some(OsStr::new("--version")) && arguments.next().is_none() {
        println!("{}", omachat_proto::version_line("omachat"));
        return ExitCode::SUCCESS;
    }

    eprintln!("omachat runtime is not implemented yet; use --version");
    ExitCode::from(2)
}
