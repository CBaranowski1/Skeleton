"""Independent evidence-derived market activation dossiers and snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from types import MappingProxyType
from typing import Mapping

from .canonical import canonicalize
from .evidence_store import EvidenceStore


ACTIVATION_GATES = (
    "rights",
    "law_terms_jurisdiction",
    "identity",
    "calendar",
    "costs_fills",
    "failures_outages",
    "settlement",
    "security",
    "evaluation",
    "tax_accounting",
    "owner_authorization",
)
_GATE_POSITION = {name: index for index, name in enumerate(ACTIVATION_GATES)}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")
_BLOCKER = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(slots=True)
class ActivationRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class DossierGate:
    name: str
    adapter_identity: str
    evidence_sha256: str
    source_class: str
    status: str
    reviewed_at: str
    expires_at: str
    blocker_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.name not in _GATE_POSITION:
            raise ActivationRejection("gate_unknown")
        if not self.adapter_identity or _SHA256.fullmatch(self.evidence_sha256) is None:
            raise ActivationRejection("gate_evidence_invalid")
        if self.source_class not in {"independent", "synthetic"}:
            raise ActivationRejection("gate_source_class_unknown")
        if self.status not in {"verified", "unverified", "conflicting", "unknown"}:
            raise ActivationRejection("gate_status_unknown")
        reviewed = _time(self.reviewed_at)
        expires = _time(self.expires_at)
        if reviewed >= expires:
            raise ActivationRejection("gate_clock_invalid")
        if (
            tuple(sorted(set(self.blocker_codes))) != self.blocker_codes
            or any(_BLOCKER.fullmatch(code) is None for code in self.blocker_codes)
        ):
            raise ActivationRejection("gate_blockers_invalid")

    def as_value(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "adapter_identity": self.adapter_identity,
                "blocker_codes": list(self.blocker_codes),
                "evidence_sha256": self.evidence_sha256,
                "expires_at": self.expires_at,
                "name": self.name,
                "reviewed_at": self.reviewed_at,
                "source_class": self.source_class,
                "status": self.status,
            }
        )


@dataclass(frozen=True, slots=True)
class MarketActivationDossier:
    adapter_identity: str
    family: str
    venue: str
    jurisdiction: str
    environment: str
    version: str
    gates: tuple[DossierGate, ...]

    def __post_init__(self) -> None:
        fields = (self.family, self.venue, self.jurisdiction, self.environment, self.version)
        if any(not value for value in fields):
            raise ActivationRejection("dossier_identity_incomplete")
        expected = "|".join(fields)
        if self.adapter_identity != expected:
            raise ActivationRejection("dossier_identity_mismatch")
        if not isinstance(self.gates, tuple) or any(not isinstance(gate, DossierGate) for gate in self.gates):
            raise ActivationRejection("dossier_gates_invalid")
        names = tuple(gate.name for gate in self.gates)
        if len(names) != len(set(names)):
            raise ActivationRejection("gate_duplicate")
        if tuple(sorted(names, key=_GATE_POSITION.__getitem__)) != names:
            raise ActivationRejection("gate_order_invalid")

    @property
    def content_sha256(self) -> str:
        return sha256(canonicalize(dict(self.as_value()))).hexdigest()

    def as_value(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "adapter_identity": self.adapter_identity,
                "environment": self.environment,
                "family": self.family,
                "gates": [dict(gate.as_value()) for gate in self.gates],
                "jurisdiction": self.jurisdiction,
                "schema_version": "skeleton.market-activation-dossier.v1",
                "venue": self.venue,
                "version": self.version,
            }
        )


@dataclass(frozen=True, slots=True)
class MarketActivationSnapshot:
    activation_id: str
    dossier_sha256: str
    adapter_identity: str
    adapter_identity_sha256: str
    state: str
    blockers: tuple[str, ...]
    observed_at: str
    canonical_bytes: bytes

    def as_status_value(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "activation_id": self.activation_id,
                "adapter_identity_sha256": self.adapter_identity_sha256,
                "blockers": list(self.blockers),
                "dossier_sha256": self.dossier_sha256,
                "state": self.state,
            }
        )


class MarketActivationEvaluator:
    """Pure derivation with optional append-only persistence through one writer."""

    def __init__(
        self,
        *,
        observed_at: datetime,
        store: EvidenceStore | None = None,
        evidence_store: EvidenceStore | None = None,
        authenticated_evidence: Mapping[str, bytes] | None = None,
        review_max_age: timedelta = timedelta(days=30),
    ) -> None:
        if not isinstance(observed_at, datetime) or observed_at.tzinfo is None:
            raise ActivationRejection("observation_time_invalid")
        self.observed_at = observed_at.astimezone(timezone.utc)
        if not isinstance(review_max_age, timedelta) or review_max_age <= timedelta(0):
            raise ActivationRejection("review_age_invalid")
        if store is not None and not isinstance(store, EvidenceStore):
            raise ActivationRejection("writer_connection_required")
        if evidence_store is not None and not isinstance(evidence_store, EvidenceStore):
            raise ActivationRejection("evidence_store_invalid")
        self.review_max_age = review_max_age
        self.store = store
        self.evidence_store = evidence_store if evidence_store is not None else store
        evidence = {} if authenticated_evidence is None else dict(authenticated_evidence)
        if any(_SHA256.fullmatch(key) is None or not isinstance(raw, bytes) for key, raw in evidence.items()):
            raise ActivationRejection("authenticated_evidence_invalid")
        self.authenticated_evidence = MappingProxyType(evidence)

    def evaluate(self, dossier: MarketActivationDossier) -> MarketActivationSnapshot:
        if not isinstance(dossier, MarketActivationDossier):
            raise ActivationRejection("dossier_required")
        by_name = {gate.name: gate for gate in dossier.gates}
        blockers: list[str] = []
        blocker_set: set[str] = set()

        def block(code: str) -> None:
            if code not in blocker_set:
                blockers.append(code)
                blocker_set.add(code)

        for name in ACTIVATION_GATES:
            gate = by_name.get(name)
            if gate is None:
                block(f"missing_{name}")
                continue
            self._authenticate_gate(gate)
            if gate.adapter_identity != dossier.adapter_identity:
                block(f"identity_mismatch_{name}")
                continue
            if gate.source_class == "synthetic":
                block(f"synthetic_only_{name}")
                continue
            if gate.status != "verified":
                block(f"{gate.status}_{name}")
                continue
            reviewed = _time(gate.reviewed_at)
            expires = _time(gate.expires_at)
            if reviewed > self.observed_at:
                block(f"future_review_{name}")
                continue
            if self.observed_at - reviewed > self.review_max_age:
                block(f"stale_{name}")
                continue
            if expires <= self.observed_at:
                block(f"expired_{name}")
                continue
            for code in gate.blocker_codes:
                block(code)
        state = "inactive" if blockers else "eligible_for_future_authorization"
        observed_at = _timestamp(self.observed_at)
        base: dict[str, object] = {
            "adapter_identity_sha256": sha256(dossier.adapter_identity.encode("utf-8")).hexdigest(),
            "blockers": blockers,
            "dossier_sha256": dossier.content_sha256,
            "observed_at": observed_at,
            "schema_version": "skeleton.market-activation-snapshot.v1",
            "state": state,
        }
        activation_id = sha256(canonicalize(base)).hexdigest()
        raw = canonicalize({**base, "activation_id": activation_id})
        snapshot = MarketActivationSnapshot(
            activation_id=activation_id,
            dossier_sha256=dossier.content_sha256,
            adapter_identity=dossier.adapter_identity,
            adapter_identity_sha256=str(base["adapter_identity_sha256"]),
            state=state,
            blockers=tuple(blockers),
            observed_at=observed_at,
            canonical_bytes=raw,
        )
        if self.store is not None:
            self._persist(snapshot)
        return snapshot

    def _authenticate_gate(self, gate: DossierGate) -> None:
        if self.evidence_store is None:
            raise ActivationRejection("evidence_store_required")
        raw = self.authenticated_evidence.get(gate.evidence_sha256)
        if raw is None:
            raise ActivationRejection(f"evidence_unauthenticated_{gate.name}")
        if sha256(raw).hexdigest() != gate.evidence_sha256:
            raise ActivationRejection(f"evidence_digest_mismatch_{gate.name}")
        expected = {
            "adapter_identity": gate.adapter_identity,
            "blocker_codes": list(gate.blocker_codes),
            "expires_at": gate.expires_at,
            "gate": gate.name,
            "reviewed_at": gate.reviewed_at,
            "source_class": gate.source_class,
            "status": gate.status,
        }
        try:
            decoded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ActivationRejection(f"evidence_body_invalid_{gate.name}") from error
        if decoded != expected or canonicalize(expected) != raw:
            raise ActivationRejection(f"evidence_body_mismatch_{gate.name}")
        row = self.evidence_store.connection.execute(
            "SELECT c.byte_length, c.quarantine, r.status, d.boundary, "
            "d.disposition, d.decided_at, d.rights_record_id, c.rights_record_id "
            "FROM content_objects AS c "
            "JOIN rights_records AS r ON r.rights_record_id=c.rights_record_id "
            "JOIN rights_decisions AS d ON d.decision_id=c.rights_decision_id "
            "WHERE c.content_sha256=?",
            (gate.evidence_sha256,),
        ).fetchone()
        if row is None:
            raise ActivationRejection(f"evidence_record_missing_{gate.name}")
        if int(row[0]) != len(raw) or str(row[1]) != "clean":
            raise ActivationRejection(f"evidence_record_invalid_{gate.name}")
        if (
            str(row[2]) != "active"
            or str(row[3]) != "activation"
            or str(row[4]) != "permit"
            or str(row[6]) != str(row[7])
            or _time(str(row[5])) > self.observed_at
        ):
            raise ActivationRejection(f"evidence_rights_invalid_{gate.name}")
        revoked = self.evidence_store.connection.execute(
            "SELECT 1 FROM rights_status_events WHERE rights_record_id=? "
            "AND status IN ('expired','revoked','terminated','superseded') "
            "AND available_at<=? LIMIT 1",
            (str(row[7]), _timestamp(self.observed_at)),
        ).fetchone()
        if revoked is not None:
            raise ActivationRejection(f"evidence_rights_revoked_{gate.name}")

    def _persist(self, snapshot: MarketActivationSnapshot) -> None:
        assert self.store is not None
        # The pre-existing Phase 8 table records execution disposition. Even a
        # future-eligible dossier remains inactive until a later authority phase.
        try:
            with self.store.transaction() as connection:
                self.store.insert(
                    "market_activation_evaluations",
                    (
                        "activation_id", "adapter_identity", "disposition",
                        "dossier_sha256", "canonical_evaluation", "evaluated_at",
                    ),
                    (
                        snapshot.activation_id, snapshot.adapter_identity, "inactive",
                        snapshot.dossier_sha256, snapshot.canonical_bytes, snapshot.observed_at,
                    ),
                    connection=connection,
                )
        except Exception as error:
            raise ActivationRejection("activation_persistence_failed") from error


def _time(value: str) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise ActivationRejection("timestamp_invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as error:
        raise ActivationRejection("timestamp_invalid") from error


def _timestamp(value: datetime) -> str:
    timespec = "microseconds" if value.microsecond else "seconds"
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")
