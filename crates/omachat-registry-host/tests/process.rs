use omachat_registry_host::{
    RegistryProcessCommand, RegistryProcessConfigError, load_registry_signing_seed,
    parse_registry_process_args,
};
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    time::Duration,
};
use tempfile::tempdir;

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn required_options_and_bounded_defaults_parse_strictly() {
    let command = parse_registry_process_args(args(&[
        "omachat-registryd",
        "--data-dir",
        "/var/lib/omachat-registry",
        "--signing-seed-file",
        "/run/secrets/registry-seed",
    ]))
    .unwrap();
    let RegistryProcessCommand::Run(config) = command else {
        panic!("expected run configuration");
    };
    assert_eq!(config.listen.to_string(), "127.0.0.1:7447");
    assert_eq!(config.limits.max_connections, 128);
    assert_eq!(config.limits.max_connections_per_ip, 8);
    assert_eq!(
        config.limits.request_admission_timeout,
        Duration::from_secs(10)
    );
    assert_eq!(config.limits.shutdown_grace, Duration::from_secs(10));
}

#[test]
fn parser_rejects_remote_bind_duplicates_and_invalid_limits() {
    assert!(matches!(
        parse_registry_process_args(args(&[
            "omachat-registryd",
            "--data-dir",
            "/tmp/state",
            "--signing-seed-file",
            "/tmp/seed",
            "--listen",
            "0.0.0.0:7447",
        ])),
        Err(RegistryProcessConfigError::NonLoopbackListen(_))
    ));
    assert!(matches!(
        parse_registry_process_args(args(&[
            "omachat-registryd",
            "--data-dir",
            "/tmp/state",
            "--data-dir",
            "/tmp/other",
            "--signing-seed-file",
            "/tmp/seed",
        ])),
        Err(RegistryProcessConfigError::DuplicateOption("--data-dir"))
    ));
    assert!(matches!(
        parse_registry_process_args(args(&[
            "omachat-registryd",
            "--data-dir",
            "/tmp/state",
            "--signing-seed-file",
            "/tmp/seed",
            "--max-connections",
            "1",
            "--max-connections-per-ip",
            "2",
        ])),
        Err(RegistryProcessConfigError::InvalidLimits)
    ));
}

#[test]
fn owner_only_regular_seed_file_loads_and_zeroizes_by_type() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("seed");
    fs::write(
        &path,
        b"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let seed = load_registry_signing_seed(&path).unwrap();
    assert_eq!(seed[0], 1);
    assert_eq!(seed[31], 32);
}

#[test]
fn seed_loader_rejects_group_access_symlinks_and_bad_encoding() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("seed");
    fs::write(&path, b"00").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        load_registry_signing_seed(&path),
        Err(RegistryProcessConfigError::SeedPermissions { mode: 0o640 })
    ));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        load_registry_signing_seed(&path),
        Err(RegistryProcessConfigError::SeedEncoding)
    ));

    let link = directory.path().join("seed-link");
    symlink(&path, &link).unwrap();
    assert!(matches!(
        load_registry_signing_seed(&link),
        Err(RegistryProcessConfigError::SeedIo { .. })
    ));
}
