# Security policy

Skeleton is pre-alpha research software. It is not approved for production,
privileged execution, custody, brokerage, or live trading.

## Supported versions

| Version | Supported |
|---|---|
| Future public mirror `main` | Security fixes will target the latest commit once the mirror opens. |
| Private canonical history | Not a public support surface. |
| Releases | No supported public release exists yet. |

## Reporting a vulnerability

Do not open a public issue, discussion, or pull request for a suspected
vulnerability, credential, private key, personal path, or private dataset.

After the public mirror is created, use **Security -> Report a vulnerability**
on GitHub. That private advisory channel is the only planned reporting route.
Until it is enabled, do not transmit sensitive details through repository
issues; retain the report privately and notify the repository owner through a
verified private channel.

Include only what is necessary to reproduce and assess the issue:

- affected commit or release;
- affected component and trust boundary;
- impact and required attacker capabilities;
- minimal reproduction using synthetic data;
- whether any credential or private material may have been exposed; and
- suggested containment, if known.

Never include a real secret in a reproduction. Replace it with an obviously
synthetic value and identify the secret type separately.

## Response principles

The maintainer will prioritize containment and evidence preservation over rapid
public disclosure. A valid report may lead to credential revocation, affected
artifact quarantine, history rewriting in the not-yet-public mirror, a private
advisory, a patched release, and coordinated disclosure.

No response-time or bounty commitment exists before the first public release.

## Scope

High-priority issues include:

- authority or capability escalation;
- signature, provenance, replay, or rollback bypass;
- unsafe path or archive handling;
- arbitrary code execution or command injection;
- secret, key, owner-identity, or private-evidence exposure;
- cross-project or cross-organ memory leakage;
- evaluator tampering or producer-controlled scoring;
- dependency or build-pipeline compromise; and
- an action path that violates the proposal-only boundary.

Findings that require live-money or unauthorized third-party testing are out of
scope. Use synthetic fixtures and owner-controlled environments only.
