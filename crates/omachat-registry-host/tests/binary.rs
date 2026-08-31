use std::process::Command;

fn registryd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_omachat-registryd"))
}

#[test]
fn help_and_version_are_standalone_success_paths() {
    let help = registryd().arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("Usage: omachat-registryd"));
    assert!(help.contains("expose only through a TLS reverse proxy"));

    let version = registryd().arg("--version").output().unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        concat!("omachat-registryd ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn missing_required_configuration_exits_nonzero_without_binding() {
    let output = registryd().output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("required registry option --data-dir is missing"));
}
