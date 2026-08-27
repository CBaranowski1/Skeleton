# Public-security audit

This report records the bounded credential and private-material audit performed
on 2026-08-27. It contains classifications and digests, never matched secret
values.

## Result

No live owner credential, provider API token, or operational private key was
confirmed in the complete history through the security-hardening commits or in
the tracked working tree.

Gitleaks 8.30.1 reported six history findings. All six are structural false
positives in safety-classifier code, synthetic hostile tests, or private
planning prose. The scanner reported thirty-five findings while traversing the
tracked tree and embedded archives: thirty-two generic-key patterns and three
private-key markers.

The three private-key findings are not Skeleton signing material. They resolve
to public PKCS#8 examples and documentation embedded in the authenticated
vendored Rust dependency closure:

| Dependency record | Record SHA-256 | Classification |
|---|---|---|
| `vendor/ed25519-3.0.0/src/pkcs8.rs` | `eb9eea2ba10e86b35f7790ddc4bc22534e6565b0bb29b87f0591c7057a1e0d29` | Upstream documentation example |
| `vendor/ed25519-3.0.0/tests/examples/pkcs8-v1.pem` | `4b4fc44435f8d20dd4e915752db1019d3936877152b95d5f39414f422b1110cd` | Upstream test fixture |
| `vendor/ed25519-3.0.0/tests/examples/pkcs8-v2.pem` | `4e571bdf609198461c86e479f323dee566d9c2beda5d9e45fcc792f8297b041e` | Upstream test fixture |
| `vendor/ed25519-dalek-3.0.0/src/lib.rs` | `6fb99fb76beff381b060d79c922284d4f0b635e83b15c3bd8adbef747ab60e63` | Upstream documentation example |

The containing crate archives match the checksums pinned in `Cargo.lock`:

- `ed25519 3.0.0`: `29fcf32e6c73d1079f83ab4d782de2d81620346a5f38c6237a86a22f8368980a`
- `ed25519-dalek 3.0.0`: `6ebaa1a2bf1290ab3bfe5a7b771d050ebffab2711c19a81691c683a5144a25de`

This classification means the markers are public test material, not that the
bundle is suitable for publication. The complete `validation/` tree remains a
denied public-export category because it also contains large binaries,
machine-specific evidence, historical dependency closures, and material whose
redistribution status has not been reviewed.

## Method

The audit used the following fail-closed checks:

1. Gitleaks scanned the complete Git history with full redaction.
2. Gitleaks scanned the working directory with archive traversal to depth
   three.
3. The custom Rust environment bundle was parsed according to its framed
   record format without printing detected values.
4. Every record containing a private-key marker was identified by path and
   SHA-256 digest.
5. Those record digests were compared with files extracted from local crate
   archives whose digests match the lockfile checksums.
6. The repository public-readiness scanner checked tracked paths, binary and
   archive exclusions, private paths, file size, and provider-token patterns.

An ignored local dependency-test environment added two generic scanner matches
in type declarations during one directory rescan. It was not tracked and is
not part of the thirty-five tracked-tree/archive findings above.

## Dependency advisory snapshot

The following advisory checks were clean on 2026-08-27:

- `pip-audit 2.10.1` reported no known vulnerabilities in
  `python/requirements-current.lock`;
- `npm audit` reported zero vulnerabilities for `typescript/package-lock.json`;
- `cargo-audit 0.22.2` reported no RustSec vulnerability in the 127-package
  `rust/contracts/Cargo.lock`; and
- `cargo-audit 0.22.2` reported no RustSec vulnerability in the 24-package
  `tools/foundation-bootstrap/Cargo.lock`.

Advisory results are time-bounded, not permanent assurances. Dependabot,
dependency review, CodeQL, and scheduled scans must remain enabled on the
eventual public mirror.

## Release decision

The private canonical repository is still not safe to make public in place.
It contains private planning, machine paths, historical validation evidence,
and inherited history that the public mirror deliberately excludes. Public
release must use the allowlisted, new-history mirror process in
`PUBLICATION.md` and must pass every committed security gate.

Any future confirmed credential changes the response immediately: revoke or
rotate it, preserve evidence privately, remove it from the public export, and
repeat both tree and history scans before publication.
