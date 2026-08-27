# Foundation Bootstrap Package Candidate

This directory builds an owner-visible Windows bootstrap package for Skeleton
Phase 11.1. It exists because the planned external
`FoundationBootstrapPackageV1` had no vendor, download, or supplied artifact.

## Trust status

The output is deliberately classified as `owner_built_local_candidate` and is
not promotion eligible. It does not claim independent vendor provenance,
trusted Authenticode publication, independent custody, or authority to create
owner keys. Both shipped executables fail closed on privileged operations.

The package is useful for closing the concrete engineering gap:

- two fixed-purpose native Windows executables;
- complete auditable Rust source and locked dependency closure;
- offline, locked build recipe;
- positive and hostile known-answer tests;
- PE import inventory;
- exact per-file SHA-256 and length inventory;
- canonical package manifest and content root;
- explicit media and build provenance;
- machine-readable blockers that prevent this local candidate from being
  mistaken for an independently supplied trust root.

## Safe operations

`FoundationBootstrapSigner.exe` supports:

- `--operation Describe`
- `--operation PackageSelfKAT`
- `--operation FoundationBootstrapSign` (always returns a typed blocked result
  in this candidate; it never creates or uses a key)

`FoundationTerminalVerifier.exe` supports:

- `--operation Describe`
- `--operation PackageSelfKAT`
- `--operation PreGenesisSafeBootstrapVerify`
- `--operation PostGenesisSafeBootstrapVerify`
- `--operation FoundationTerminalVerify`

The three verification operations authenticate the package and then return its
truthful promotion disposition. For this candidate that disposition is
`blocked`.

## Build

Run from an ordinary, non-elevated PowerShell session:

```powershell
pwsh -NoProfile -File .\build-package.ps1
```

The script builds and tests with Cargo `--locked --offline`, stages a complete
package in the OS temporary directory, finalizes its content-addressed
manifest, verifies the staged copy, copies only to the exact USB target, and
verifies the USB copy again. It refuses a non-USB `R:` target or a non-empty
package directory.

No package operation provisions a key, changes an ACL, requests elevation,
stops OneDrive, installs a service, or writes outside the selected package
directory.
