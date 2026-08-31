# Arch package preflight

The tagged PKGBUILD intentionally contains a failing checksum marker until the
owner authorizes and publishes `v0.0.1`. Replace it with `sha256sum` output for
the exact release archive; never use `SKIP` for the tagged package.

Build locally in a clean chroot:

```sh
extra-x86_64-build
namcap PKGBUILD omachat-0.0.1-1-x86_64.pkg.tar.zst
```

The `-git` package is independently buildable from the default branch. Neither
package edits user configuration, enables linger, enables the service, installs
a polkit rule, or publishes anything to the AUR.

After an owner-authorized release commit exists, create deterministic source
and checksum files with `scripts/package-release.sh 0.0.1 COMMIT OUTPUT_DIR`.
Insert that exact SHA-256 into the tagged PKGBUILD before its clean-chroot run.
