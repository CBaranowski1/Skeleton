# Trust Boundary

## What this candidate proves

- The package bytes are reproducibly tied to source, a Cargo lock, compiler
  identity, PE import inventory, KAT output, and a canonical SHA-256 manifest.
- The two shipped executables expose closed operation names and reject unknown
  arguments.
- Package verification rejects missing, extra, changed, non-regular, oversized,
  duplicate, unsafe-path, non-canonical, or root-mismatched material.
- Privileged signer behavior is structurally disabled in this build.

## What this candidate does not prove

- Independent vendor authorship or acquisition.
- An externally trusted Authenticode/PKCS#7 chain.
- Independent custody before the owner received the bytes.
- Hardware-backed owner presence or protected-machine import.
- Correct provisioning, DACL, service, grant, elevation, or teardown behavior.
- Authorization to satisfy or bypass Phase 11.1 Plan 60 or Plan 61.

## Required promotion work

1. Revise the Phase 11.1 pre-root design from an imaginary vendor prerequisite
   to a concrete owner-built/reviewer-approved ceremony, or obtain a genuinely
   independent package.
2. Receive a fresh independent source and plan review over exact committed
   bytes.
3. Add a separately controlled trusted code-signing identity and verify its
   certificate lifecycle.
4. Implement and adversarially test the owner-present CNG provisioning path
   under an independently controlled principal.
5. Rebuild on a clean host, reproduce the package root, and record custody from
   build through read-only media handoff.

Until every item is complete, `promotion_eligible` remains `false` and all
authority-bearing operations return `blocked`.
