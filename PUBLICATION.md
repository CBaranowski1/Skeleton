# Public release policy

Skeleton is published through a curated public mirror; the private canonical
repository is not itself the release artifact. Public visibility is a security
and provenance boundary, not a repository setting to flip.

## Release model

```text
private canonical repository
  -> authenticated export manifest
  -> reviewed path allowlist and redactions
  -> source, history, archive, dependency, and license scans
  -> clean-room build and tests
  -> clean public mirror repository
```

The public mirror starts with new history. Private planning, owner evidence,
hardware records, and internal recovery history remain in the canonical
repository.

## Current release status

As of the 2026-08-27 clean-room audit, the owner selected Apache-2.0 and the
public-subset release gates pass.

The verified release candidate has the following properties:

- the exporter produces 303 hash-allowlisted files plus one deterministic
  provenance record from a named private source commit;
- the public-readiness scanner passes with the canonical Apache-2.0 `LICENSE`;
- the new root commit passes Git's whitespace check;
- Gitleaks 8.30.1 reports zero findings in both the one-commit history and the
  exported directory;
- the complete public Python inventory passes 25 tests, TypeScript passes six
  runtime tests and strict type-checking, Rust passes seven contract tests, and
  the foundation bootstrap passes six tests;
- npm audit and pip-audit report no known vulnerabilities; the unchanged Rust
  locks retain their clean cargo-audit result from the private security audit;
  and
- private planning, validation evidence, machine configuration, historical
  vulnerable locks, and owner-specific material are absent from the allowlist.

The canonical checkout now lives on a non-synchronized local volume and is
backed up to the private `Skeleton-Private` GitHub repository. The public remote
and legacy synchronized checkout are fetch-only locally. A hash-allowlisted,
commit-addressed exporter and exact-path candidate manifest now exist, but the
generated candidate is releasable only after the exact license-bearing root
commit passes every gate and receives owner approval.

No confirmed live provider credential or operational private key was identified
by the bounded scans. That does not make the canonical repository publishable:
every exported byte must still pass the mirror gates before release.

## Default exclusions

The first public mirror excludes these categories unless a later review adds an
explicitly identified artifact:

- `.planning/` and all owner/planning history;
- `validation/` bundles and generated release evidence;
- secrets, credentials, signing material, owner manifests, and hardware
  identities;
- local databases, journals, caches, logs, crash dumps, and test outputs;
- model weights, adapters, embeddings, private datasets, and evaluation task
  packs;
- machine-specific paths, removable-drive instructions, and local environment
  inventories;
- binaries and archives without provenance, checksums, license review, and a
  distribution decision; and
- sibling-project code, data, configuration, and history.

The `.gitignore` prevents many new local artifacts but is not an export policy.
Tracked or historical files remain tracked until explicitly removed from the
public export.

## Candidate public contents

Only reviewed files may enter the mirror. The intended starting set is:

- source code and small deterministic tests;
- language-neutral contracts and synthetic fixtures;
- public documentation and community health files;
- reproducible dependency manifests and lockfiles after advisory review;
- small attestations needed to verify published claims; and
- license, notices, citation metadata, and an SBOM.

This list is intent, not an automatic glob allowlist. Each exported path must be
present in the authenticated export manifest.

## Required release gates

1. Keep canonical Git storage on a non-synchronized local volume with a
   recoverable private backup.
2. Keep owner planning and historical evidence in retained private history.
3. Select the project and dependency-license policy.
4. Keep current dependency locks advisory-clean and exclude vulnerable
   historical lock evidence.
5. Generate the public tree from an explicit source commit and the reviewed,
   exact-path export manifest.
6. Run private-path, secret, private-key, archive, binary, dependency,
   provenance, and license scans over both the exported tree and its new
   history.
7. Build and test the export in a clean environment with no access to the
   private repository.
8. Review the exact initial commit and all workflow permissions.
9. Obtain explicit owner approval before creating or changing a public
   repository.

## GitHub settings after mirror creation

- use `main` as the protected default branch;
- require pull requests, conversation resolution, and the committed checks;
- restrict force pushes and branch deletion;
- enable private vulnerability reporting;
- enable secret scanning and push protection;
- enable the dependency graph, Dependabot alerts, and security updates;
- enable CodeQL/default code scanning where supported;
- restrict GitHub Actions to reviewed actions and require full commit-SHA pins;
- keep workflow token permissions read-only unless a job documents a narrower
  write need; and
- review every release artifact and provenance attestation before publication.

## No direct-publication rule

Do not attach a public remote to the private canonical history, change its
visibility, or copy its `.git` directory. The public repository must be created
from the reviewed export as a new history after every gate above passes.
