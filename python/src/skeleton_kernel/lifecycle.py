"""Deterministic domain-neutral lifecycle transitions."""

from __future__ import annotations

from dataclasses import dataclass, replace as dataclass_replace
from types import MappingProxyType
from typing import Any

from .canonical import canonicalize, sha256_hex


LIFECYCLE_STATES = frozenset(
    {
        "absent",
        "active",
        "completed",
        "failed",
        "pending",
        "rejected",
        "removed",
        "suspended",
    }
)

LEGAL_TRANSITIONS = MappingProxyType(
    {
        "absent": frozenset({"active", "pending", "rejected", "removed"}),
        "pending": frozenset(
            {"active", "completed", "failed", "rejected", "removed", "suspended"}
        ),
        "active": frozenset({"completed", "failed", "removed", "suspended"}),
        "suspended": frozenset({"active", "completed", "failed", "removed"}),
        "failed": frozenset({"pending", "removed"}),
        "rejected": frozenset({"pending", "removed"}),
        "completed": frozenset({"removed"}),
        "removed": frozenset(),
    }
)


@dataclass(slots=True)
class LifecycleRejection(ValueError):
    """Stable rejection with no untrusted payload echo."""

    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class LifecycleEvent:
    event_id: str
    subject_type: str
    subject_id: str
    prior_state: str
    new_state: str
    prior_state_sha256: str
    event_sha256: str
    cause_code: str
    cause_evidence_sha256: str
    authorization_mode: str
    authorization_evidence_sha256: str
    occurred_at: str
    canonical_bytes: bytes

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
        *,
        prior_state_sha256: str,
    ) -> "LifecycleEvent":
        if set(value) != {
            "schema_version",
            "event_id",
            "subject",
            "prior_state",
            "new_state",
            "cause",
            "authorization",
            "occurred_at",
        }:
            raise LifecycleRejection("invalid_lifecycle_shape")
        if value["schema_version"] != "skeleton.lifecycle-event.v1":
            raise LifecycleRejection("unknown_lifecycle_schema")
        subject = value["subject"]
        cause = value["cause"]
        authorization = value["authorization"]
        if not all(isinstance(item, dict) for item in (subject, cause, authorization)):
            raise LifecycleRejection("invalid_lifecycle_shape")
        prior_state = value["prior_state"]
        new_state = value["new_state"]
        validate_transition(prior_state, new_state)
        canonical_bytes = canonicalize(value)
        return cls(
            event_id=_lower_hash(value["event_id"], "invalid_event_id"),
            subject_type=_identifier(subject.get("subject_type")),
            subject_id=_lower_hash(subject.get("subject_id"), "invalid_subject_id"),
            prior_state=prior_state,
            new_state=new_state,
            prior_state_sha256=_lower_hash(
                prior_state_sha256, "invalid_prior_state_hash"
            ),
            event_sha256=sha256_hex(canonical_bytes),
            cause_code=_identifier(cause.get("code")),
            cause_evidence_sha256=_lower_hash(
                cause.get("evidence_sha256"), "invalid_cause_evidence"
            ),
            authorization_mode=_identifier(authorization.get("mode")),
            authorization_evidence_sha256=_lower_hash(
                authorization.get("evidence_sha256"),
                "invalid_authorization_evidence",
            ),
            occurred_at=_identifier(value["occurred_at"]),
            canonical_bytes=canonical_bytes,
        )

    def replace(self, **changes: str) -> "LifecycleEvent":
        if "prior_state_sha256" in changes:
            _lower_hash(changes["prior_state_sha256"], "invalid_prior_state_hash")
        return dataclass_replace(self, **changes)


def validate_transition(prior_state: str, new_state: str) -> None:
    if prior_state not in LIFECYCLE_STATES or new_state not in LIFECYCLE_STATES:
        raise LifecycleRejection("unknown_lifecycle_state")
    if new_state not in LEGAL_TRANSITIONS[prior_state]:
        raise LifecycleRejection("illegal_transition")


def _lower_hash(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise LifecycleRejection(code)
    return value


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise LifecycleRejection("invalid_identifier")
    return value
