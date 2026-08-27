# Offline Build Recipe

## Required inputs

- Windows x86-64 host
- Rust `1.97.1` MSVC toolchain
- Cargo registry/cache containing every coordinate in `Cargo.lock`
- Windows SDK `dumpbin.exe` for import observation
- PowerShell 7
- An empty USB target at
  `R:\SkeletonOwnerOffline\Phase11_1\FoundationBootstrapPackageV1`

## Commands

The authoritative entry point is `build-package.ps1`. Its build commands are:

```text
cargo test --manifest-path Cargo.toml --locked --offline
cargo build --manifest-path Cargo.toml --release --locked --offline
```

The script then copies the two release executables and complete source closure
to a fresh OS-temporary staging directory, records compiler/dependency/import/
media facts, runs built-in KATs, and invokes the non-shipped
`foundation-package-builder.exe` to create:

```text
package-manifest.json
package-root.txt
```

The canonical package root is SHA-256 over RFC 8785/JCS canonical manifest
bytes. The manifest's inventory root is a separately domain-framed SHA-256 over
the sorted path, length, and file-digest tuples.

The staged package must pass `FoundationTerminalVerifier.exe --operation
PackageSelfKAT` before copying. The USB copy must pass the same operation from
the USB path. Any failure leaves the existing USB target untouched.

## Prohibited substitutions

- No online Cargo resolution or update.
- No arbitrary target path by default.
- No copy over an existing non-empty target.
- No generated vendor, custody, or trusted-signing claim.
- No execution of `FoundationBootstrapSign` during build or packaging.
