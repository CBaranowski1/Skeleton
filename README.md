# Skeleton

Skeleton is an owner-controlled cognition kernel for persistent identity,
evidence, memory, evaluation, bounded learning, and reversible change. The
kernel is the stable skeleton of the system; developer tooling, agent control,
research, and trading are replaceable organs with separate permissions and
versioned contracts.

Skeleton is not a trading bot, a live execution system, or a finished autonomous
developer. It is pre-alpha research software and must remain proposal-only until
its independent evaluation and authority gates are proven.

## Current status

**Public pre-alpha research software. No production authority.**

The 2026-08-27 audit found a substantial deterministic foundation but not yet a
complete local cognition product:

- Python implements the semantic kernel, isolated SQLite owners, evidence,
  memory, agent, metabolism, and plasticity reference behavior.
- Ninety-two JSON Schemas and forty-four fixture files define the principal
  cross-language contract boundary.
- Rust provides an independent contract verifier and a small native Windows
  foundation-bootstrap package.
- TypeScript provides strict contract projections and a read-only owner-status
  surface.
- Hostile tests exercise replay, rollback, crash windows, mutation denial,
  fencing, and cross-runtime conformance.

The central product claim is still unproven. No production local-model adapter,
repository work object, proposal-only patch loop, or independently scored
developer task is connected end to end.

## Active goal: the first functioning organ

Phase 13.1 is the current MVP boundary. On one small owner-approved repository
task, Skeleton must:

1. use one real model through a provider-neutral local interface;
2. retrieve relevant stored context;
3. produce a proposal-only patch;
4. run a fixed evaluator the producing model cannot change;
5. record the attempt and outcome;
6. update one reversible retrieval or routing rule;
7. improve on a matched second task;
8. preserve the result across restart; and
9. roll the learned change back without changing identity or authority.

Model-weight training, privileged execution, an agent mesh, a trading
integration, and a broad UI are deliberately outside this slice.

## Near-term roadmap

- **Stabilize the repository:** move canonical Git storage off synchronized
  folders, classify the existing dirty planning changes, configure a private
  remote, and prove a clean checkout.
- **Prove Phase 13.1:** connect the local cortex, developer work object,
  proposal path, independent evaluator, persistence, restart, and rollback.
- **Reduce change cost:** extract typed internal package boundaries before
  considering new services or language rewrites.
- **Maintain the publication boundary:** generate the public mirror only from
  the reviewed export, keep private evidence and large bundles excluded, and
  require clean-room security and build gates for every published update.

See [PUBLICATION.md](PUBLICATION.md) for the release boundary and remaining
public-readiness blockers.

## Architecture and language boundaries

| Boundary | Current implementation | Direction |
|---|---|---|
| Kernel semantics and stores | Python 3.14 | Remains the semantic oracle until an independent implementation proves parity. |
| Contracts | JSON Schema, canonical JSON, fixtures | Independently versioned boundary consumed by every language. |
| Native bootstrap and contract verifier | Rust 2024 | Retained where native isolation and independent verification justify it. |
| Owner status surface | TypeScript and browser JavaScript | Read-only; no authority or execution ownership. |
| Durable invariants | SQLite and SQL | One writer per authoritative domain; no microservice split without evidence. |
| Local cortex | Not implemented | Separate loopback process behind a minimal provider-neutral port. |
| Optimized kernels | Not implemented | C++, CUDA, or Rust only after a reproducible benchmark fails a named requirement. |

## Repository layout

| Path | Purpose |
|---|---|
| `contracts/` | Language-neutral schemas and conformance fixtures. |
| `python/` | Kernel reference implementation and the main test suites. |
| `rust/contracts/` | Independent Rust contract verifier. |
| `tools/foundation-bootstrap/` | Native Windows bootstrap candidate and verifier. |
| `typescript/` | Contract projections and read-only owner status client. |
| `sql/` | Durable schema and migration invariants. |
| `scripts/` | Authenticated bootstrap and phase verification entry points. |
| `web/` | Checked-in read-only status surface. |
| `.planning/` | Private canonical planning and evidence; excluded from the planned public mirror. |
| `validation/` | Large internal validation artifacts; excluded pending provenance and redistribution review. |

The separate EdgeTrade codebase is a reference source for a possible future
trading organ. It is not vendored here, and Skeleton must not inherit its
identity, credentials, data, or permissions implicitly.

## Development snapshot

The fully authenticated environment is currently Windows x86-64 with CPython
3.14.6, Node.js 26.4.0, npm 11.17.0, Rust/Cargo 1.97.1 MSVC, Windows
PowerShell 5.1, and PowerShell 7 for native bootstrap packaging.

Portable checks used by GitHub Actions are intentionally narrower than the
authenticated release gates:

```powershell
python -m pip install --require-hashes --only-binary=:all: -r python/requirements-current.lock
python -m compileall -q python/src
python -m pytest -q python/tests/contracts/test_protocol_schemas.py -k "not index_covers_protocol_and_jcs_sources_exactly"
python -m pytest -q python/tests/kernel/test_proposal_membrane.py -k signature_signer_boundary_round_trips_raw_ed25519

Push-Location typescript
npm ci
& .\node_modules\@typescript\typescript-win32-x64\lib\tsc.exe --noEmit
Pop-Location

cargo test --manifest-path rust/contracts/Cargo.toml --locked --lib -- --skip indexed_golden_jcs_signature_and_trust_corpus_matches
cargo test --manifest-path tools/foundation-bootstrap/Cargo.toml --locked
```

The complete phase verifier suite is Windows-specific and still requires the
authenticated dependency closures created by the bootstrap scripts. A clean
source checkout is not yet self-demonstrating; fixing that is a current goal,
not a capability this README claims already exists.

Known fixture/schema drift is excluded only from this narrow baseline. The
wider Python core/envelope diagnostic reports 58 passes and 5 failures because
`canonical-event.schema.json` includes `market` while fixture-index cases omit
the expected `id`. The protocol index test has the same stale-index class of
failure, the Rust indexed-corpus test rejects a malformed fixture record, and
the TypeScript runtime suites do not currently run from a clean checkout.
Publication requires restoring every diagnostic rather than broadening these
exclusions.

## Security

Do not put credentials, private keys, owner manifests, model weights, local
databases, private evidence, or real evaluation task packs in Git. The expanded
`.gitignore` prevents common new artifacts, but it cannot remove material that
is already tracked or present in history.

Report suspected vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). The bounded credential investigation and its
non-secret classifications are recorded in [SECURITY-AUDIT.md](SECURITY-AUDIT.md).
Do not open a public issue for a vulnerability or credential exposure.

## Contributing and conduct

The contribution workflow is documented in [CONTRIBUTING.md](CONTRIBUTING.md),
and all project spaces follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). External
contributions are accepted only through the public mirror after its required
checks pass.

## Publication and license

The canonical repository contains private planning, machine-specific evidence,
large validation bundles, and retained internal history. It must not be made
public in place. Publication uses a clean repository created from a reviewed,
allowlisted export with no inherited private history.

Skeleton is licensed under the Apache License, Version 2.0. See
[LICENSE](LICENSE).

Skeleton provides no financial advice, custody, brokerage, or live-trading
service.
