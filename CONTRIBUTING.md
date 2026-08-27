# Contributing to Skeleton

Skeleton accepts bounded, proposal-first contributions through its curated
public mirror. The private canonical repository remains a separate security
boundary and is never the contribution target.

## Before contributing

- Read `README.md`, `SECURITY.md`, `PUBLICATION.md`, and `CODE_OF_CONDUCT.md`.
- Do not submit private planning, owner evidence, credentials, machine paths,
  model weights, local databases, or real evaluation task packs.
- Do not move authority, evaluation, or persistence boundaries without an
  explicit contract and hostile tests.
- Open a proposal before a large architectural change or new language/runtime.
- Report vulnerabilities privately; never use a public issue for security
  details.

## Change workflow

1. Create a focused branch from the protected default branch.
2. Keep one logical change per pull request.
3. Add or update deterministic tests before claiming behavior changed.
4. Preserve canonical serialization, append-only history, replay, rollback,
   and failure-denial behavior.
5. Run the portable checks documented in `README.md`.
6. Complete the pull-request checklist and disclose substantial generated-code
   assistance so reviewers can assess provenance and licensing.
7. Wait for required reviews and checks; do not force-push after review without
   explaining the replacement commits.

## Design expectations

- Evidence outranks agreement or model confidence.
- Producing code must not control its own evaluator.
- Components receive only the capabilities and data they need.
- A new service, repository, or implementation language needs a measured
  isolation, release, dependency, reliability, or performance reason.
- Python remains the semantic oracle until an independent implementation proves
  parity on the same fixtures and hostile cases.
- No contributor may add live execution, custody, signing, withdrawal, wager,
  or external-funds authority through an ordinary pull request.

## Commits and pull requests

Use clear imperative commit subjects. Pull requests should explain:

- the problem and bounded solution;
- trust boundaries and failure modes affected;
- tests and independent evidence;
- migration and rollback behavior;
- dependency, license, and public-export impact; and
- any remaining uncertainty.

The project may request changes, narrow a proposal, or reject work that adds
architecture without demonstrated usefulness.

## License

Skeleton is licensed under Apache-2.0. Unless explicitly stated otherwise, an
intentional contribution submitted for inclusion in Skeleton is provided under
the same license, as described in Section 5 of the license.
