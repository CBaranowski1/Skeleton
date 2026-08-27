"""Immutable, deny-by-default rights and legal-use authority.

The evaluator is deliberately local and side-effect free except for its append-only
decision/status ledger.  Persistence remains owned by :mod:`evidence_authority`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from threading import RLock
from typing import Any

from .canonical import canonicalize, sha256_hex


EVALUATOR_VERSION = "skeleton.rights-evaluator.v1"
_HASH_ZERO = "0" * 64


class UseBoundary(StrEnum):
    INGEST = "ingest"
    RETRIEVAL = "retrieval"
    PROMPT = "prompt"
    TRAINING = "training"
    EVALUATION = "evaluation"
    EXPORT = "export"
    BACKUP = "backup"
    ACTIVATION = "activation"


class LegalAuthorityClass(StrEnum):
    DOCUMENTED_LAW = "documented_law"
    PROVIDER_CONTRACT = "provider_contract"
    OWNER_POLICY = "owner_policy"
    UNRESOLVED_COUNSEL = "unresolved_counsel_question"


class AcquisitionMethod(StrEnum):
    DOCUMENTED_API = "documented_api"
    LICENSED_FILE = "licensed_file"
    OWNER_DOWNLOAD = "owner_download"
    PROVIDED_FIXTURE = "provided_fixture"
    PUBLIC_VIEWABLE = "public_viewable"
    UNDOCUMENTED_ENDPOINT = "undocumented_endpoint"


class QuarantineClass(StrEnum):
    LEGACY = "legacy"
    SYNTHETIC = "synthetic"
    STALE = "stale"
    REVOKED_RIGHTS = "revoked_rights"
    CONTAMINATED = "contaminated"


@dataclass(slots=True)
class RightsRejection(ValueError):
    """A closed rejection that cannot carry submitted content or paths."""

    code: str
    redacted: bool = True
    decision_id: str | None = None

    def __str__(self) -> str:
        return self.code


_POLICY_FIELDS = (
    "purposes",
    "territories",
    "display",
    "storage",
    "derivation",
    "training",
    "transmission",
    "backup",
    "attribution",
    "retention",
    "deletion",
    "audit",
    "termination",
    "acquisition_methods",
    "processing_destinations",
)


def _tuple_strings(value: Any) -> tuple[str, ...]:
    if (
        not isinstance(value, (list, tuple))
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise RightsRejection("rights_record_incomplete")
    return tuple(sorted(set(value)))


def _boundary_pairs(value: Any) -> tuple[tuple[str, bool], ...]:
    expected = {boundary.value for boundary in UseBoundary}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise RightsRejection("rights_record_incomplete")
    if any(type(value[name]) is not bool for name in expected):
        raise RightsRejection("rights_record_incomplete")
    return tuple((name, bool(value[name])) for name in sorted(expected))


def _destination_pairs(value: Any) -> tuple[tuple[str, str], ...]:
    if (
        not isinstance(value, (list, tuple))
        or not value
        or any(
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not all(isinstance(part, str) and part for part in item)
            for item in value
        )
    ):
        raise RightsRejection("rights_record_incomplete")
    return tuple(sorted(set((str(item[0]), str(item[1])) for item in value)))


@dataclass(frozen=True, slots=True)
class RightsRecord:
    rights_record_id: str
    legal_terms_id: str
    version: int
    status: str
    effective_from: str
    effective_to: str | None
    supersedes_rights_record_id: str | None
    boundaries: tuple[tuple[str, bool], ...]
    purposes: tuple[str, ...]
    territories: tuple[str, ...]
    display: tuple[str, ...]
    storage: tuple[str, ...]
    derivation: tuple[str, ...]
    training: tuple[str, ...]
    transmission: tuple[str, ...]
    backup: tuple[str, ...]
    attribution: tuple[str, ...]
    retention: tuple[str, ...]
    deletion: tuple[str, ...]
    audit: tuple[str, ...]
    termination: tuple[str, ...]
    acquisition_methods: tuple[str, ...]
    processing_destinations: tuple[tuple[str, str], ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RightsRecord":
        required = {
            "rights_record_id", "legal_terms_id", "version", "status",
            "effective_from", "effective_to", "supersedes_rights_record_id",
            "boundaries", *_POLICY_FIELDS,
        }
        if set(value) != required:
            raise RightsRejection("rights_record_incomplete")
        version = value["version"]
        if type(version) is not int or version < 1:
            raise RightsRejection("rights_record_incomplete")
        if value["status"] not in {
            "active", "expired", "revoked", "terminated", "superseded", "unknown"
        }:
            raise RightsRejection("rights_unknown")
        record = cls(
            rights_record_id=_hash(value["rights_record_id"], "rights_record_incomplete"),
            legal_terms_id=_hash(value["legal_terms_id"], "rights_record_incomplete"),
            version=version,
            status=str(value["status"]),
            effective_from=_timestamp_text(value["effective_from"], "rights_record_incomplete"),
            effective_to=(
                None
                if value["effective_to"] is None
                else _timestamp_text(value["effective_to"], "rights_record_incomplete")
            ),
            supersedes_rights_record_id=(
                None
                if value["supersedes_rights_record_id"] is None
                else _hash(value["supersedes_rights_record_id"], "rights_record_incomplete")
            ),
            boundaries=_boundary_pairs(value["boundaries"]),
            purposes=_tuple_strings(value["purposes"]),
            territories=_tuple_strings(value["territories"]),
            display=_tuple_strings(value["display"]),
            storage=_tuple_strings(value["storage"]),
            derivation=_tuple_strings(value["derivation"]),
            training=_tuple_strings(value["training"]),
            transmission=_tuple_strings(value["transmission"]),
            backup=_tuple_strings(value["backup"]),
            attribution=_tuple_strings(value["attribution"]),
            retention=_tuple_strings(value["retention"]),
            deletion=_tuple_strings(value["deletion"]),
            audit=_tuple_strings(value["audit"]),
            termination=_tuple_strings(value["termination"]),
            acquisition_methods=_tuple_strings(value["acquisition_methods"]),
            processing_destinations=_destination_pairs(value["processing_destinations"]),
        )
        if record.effective_to is not None and _parse_time(record.effective_to) <= _parse_time(record.effective_from):
            raise RightsRejection("rights_record_incomplete")
        return record

    def boundary_permitted(self, boundary: UseBoundary) -> bool:
        return dict(self.boundaries)[boundary.value]


@dataclass(frozen=True, slots=True)
class LegalTermsRecord:
    legal_terms_id: str
    authority_class: LegalAuthorityClass
    version: int
    status: str
    jurisdiction: str
    acquisition_method: AcquisitionMethod
    automation_grant: str
    effective_from: str
    effective_to: str | None
    recorded_at: str
    applicable: bool
    resolved: bool
    supersedes_legal_terms_id: str | None = None


@dataclass(frozen=True, slots=True)
class RightsStatusEvent:
    status_event_id: str
    rights_record_id: str
    prior_status: str
    status: str
    available_at: str


@dataclass(frozen=True, slots=True)
class UseRequest:
    subject_sha256: str
    evidence_sha256: str
    boundary: UseBoundary
    purpose: str
    territory: str
    display: str
    storage: str
    derivation: str
    training: str
    transmission: str
    backup: str
    attribution: str
    retention: str
    deletion: str
    audit: str
    termination: str
    acquisition_method: str
    processing_boundary: str
    destination: str
    requested_at: str
    nonce: int = 0


@dataclass(frozen=True, slots=True)
class RightsDecision:
    decision_id: str
    request_id: str
    subject_sha256: str
    evidence_sha256: str
    rights_record_id: str
    legal_terms_id: str
    boundary: UseBoundary
    purpose: str
    territory: str
    display: str
    storage: str
    derivation: str
    training: str
    transmission: str
    backup: str
    attribution: str
    retention: str
    deletion: str
    audit: str
    termination: str
    acquisition_method: str
    processing_boundary: str
    destination: str
    evaluator_version: str
    decided_at: str
    disposition: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class RightsEvaluatorSnapshot:
    protected_relations: tuple[str, ...]
    raw_objects: int
    canonical_events: int
    redacted_denials: int
    permit_decisions: int
    status_events: int


@dataclass(frozen=True, slots=True)
class QuarantineDisposition:
    eligible: bool
    classes: tuple[QuarantineClass, ...]
    rights_record_id: str | None
    evaluated_at: str
    evaluator_version: str = EVALUATOR_VERSION


class RightsEvaluator:
    """Deterministic append-only fold over rights, legal, and status records."""

    def __init__(
        self,
        *,
        rights_records: Sequence[RightsRecord],
        legal_terms: Sequence[LegalTermsRecord],
        clock: Callable[[], datetime],
    ) -> None:
        if not rights_records:
            raise RightsRejection("rights_record_missing")
        self._rights_records = tuple(rights_records)
        self._legal_terms = tuple(legal_terms)
        self._clock = clock
        self._status_events: list[RightsStatusEvent] = []
        self._permits: list[RightsDecision] = []
        self._denials: list[tuple[str, str, str]] = []
        self._decisions: dict[str, RightsDecision] = {}
        self._counter = 0
        self._lock = RLock()
        self.network_request_count = 0
        self._validate_registers()

    @classmethod
    def from_fixture_records(
        cls,
        records: Sequence[Mapping[str, Any]],
        clock: Callable[[], datetime],
        *,
        respect_boundary_flags: bool = False,
    ) -> "RightsEvaluator":
        by_id = {
            str(record.get("id")): record
            for record in records
            if isinstance(record, Mapping)
        }
        rights_payload = _payload(by_id.get("rights-record-valid"))
        legal_payload = _payload(by_id.get("legal-terms-record-valid"))
        rights_id = str(rights_payload.get("rights_record_id", "91" * 32))
        legal_id = str(rights_payload.get("legal_terms_id", "61" * 32))
        schema_boundaries = rights_payload.get("boundaries")
        if not isinstance(schema_boundaries, Mapping):
            schema_boundaries = {boundary.value: True for boundary in UseBoundary}
        boundaries = {
            boundary.value: (
                bool(schema_boundaries.get(boundary.value))
                if respect_boundary_flags
                else True
            )
            for boundary in UseBoundary
        }
        policy = _complete_fixture_policy(
            rights_record_id=rights_id,
            legal_terms_id=legal_id,
            status=str(rights_payload.get("status", "active")),
            effective_from=str(rights_payload.get("effective_from", "2026-01-01T00:00:00Z")),
            effective_to=rights_payload.get("effective_to", "2026-12-31T23:59:59Z"),
            boundaries=boundaries,
        )
        provider = LegalTermsRecord(
            legal_terms_id=legal_id,
            authority_class=LegalAuthorityClass.PROVIDER_CONTRACT,
            version=1,
            status="active",
            jurisdiction=str(legal_payload.get("jurisdiction", "US")),
            acquisition_method=AcquisitionMethod(str(legal_payload.get("acquisition_method", "owner_download"))),
            automation_grant=str(legal_payload.get("automation_grant", "local_processing_only")),
            effective_from=str(legal_payload.get("effective_from", "2026-01-01T00:00:00Z")),
            effective_to=str(legal_payload.get("effective_to", "2026-12-31T23:59:59Z")),
            recorded_at=str(legal_payload.get("recorded_at", legal_payload.get("effective_from", "2026-01-01T00:00:00Z"))),
            applicable=True,
            resolved=True,
        )
        legal_records = (
            LegalTermsRecord(
                legal_terms_id=_digest("documented-law", legal_id),
                authority_class=LegalAuthorityClass.DOCUMENTED_LAW,
                version=1,
                status="active",
                jurisdiction="US",
                acquisition_method=provider.acquisition_method,
                automation_grant="local_processing_only",
                effective_from=provider.effective_from,
                effective_to=provider.effective_to,
                recorded_at=provider.recorded_at,
                applicable=True,
                resolved=True,
            ),
            provider,
            LegalTermsRecord(
                legal_terms_id=_digest("owner-policy", legal_id),
                authority_class=LegalAuthorityClass.OWNER_POLICY,
                version=1,
                status="active",
                jurisdiction="US",
                acquisition_method=provider.acquisition_method,
                automation_grant="local_processing_only",
                effective_from=provider.effective_from,
                effective_to=provider.effective_to,
                recorded_at=provider.recorded_at,
                applicable=True,
                resolved=True,
            ),
            LegalTermsRecord(
                legal_terms_id=_digest("counsel-question", legal_id),
                authority_class=LegalAuthorityClass.UNRESOLVED_COUNSEL,
                version=1,
                status="active",
                jurisdiction="US",
                acquisition_method=provider.acquisition_method,
                automation_grant="prohibited",
                effective_from=provider.effective_from,
                effective_to=provider.effective_to,
                recorded_at=provider.recorded_at,
                applicable=False,
                resolved=False,
            ),
        )
        return cls(
            rights_records=(RightsRecord.from_mapping(policy),),
            legal_terms=legal_records,
            clock=clock,
        )

    @property
    def legal_authority_classes(self) -> tuple[str, ...]:
        order = {
            LegalAuthorityClass.DOCUMENTED_LAW: 0,
            LegalAuthorityClass.PROVIDER_CONTRACT: 1,
            LegalAuthorityClass.OWNER_POLICY: 2,
            LegalAuthorityClass.UNRESOLVED_COUNSEL: 3,
        }
        return tuple(
            item.authority_class.value
            for item in sorted(self._legal_terms, key=lambda item: order[item.authority_class])
        )

    @property
    def applicable_unresolved_counsel_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                item.legal_terms_id
                for item in self._legal_terms
                if item.authority_class is LegalAuthorityClass.UNRESOLVED_COUNSEL
                and item.applicable
                and not item.resolved
            )
        )

    def current_rights_record(self) -> RightsRecord:
        return max(self._rights_records, key=lambda item: (item.version, item.rights_record_id))

    def current_status(self, rights_record_id: str) -> str:
        records = tuple(
            record for record in self._rights_records
            if record.rights_record_id == rights_record_id
        )
        if not records:
            raise RightsRejection("rights_record_missing")
        status = max(records, key=lambda item: item.version).status
        events = sorted(
            (
                event for event in self._status_events
                if event.rights_record_id == rights_record_id
            ),
            key=lambda item: (item.available_at, item.status_event_id),
        )
        for event in events:
            status = event.status
        return status

    def append_status_event(
        self,
        *,
        rights_record_id: str,
        status: str,
        available_at: str,
    ) -> RightsStatusEvent:
        if status not in {"active", "expired", "revoked", "terminated", "superseded", "unknown"}:
            raise RightsRejection("rights_unknown")
        _timestamp_text(available_at, "rights_status_event_malformed")
        with self._lock:
            if any(
                event.rights_record_id == rights_record_id
                and event.status == status
                and event.available_at == available_at
                for event in self._status_events
            ):
                raise RightsRejection("rights_status_event_replay")
            prior = self.current_status(rights_record_id)
            event_id = _digest(
                "rights-status-event",
                rights_record_id,
                prior,
                status,
                available_at,
            )
            if any(event.status_event_id == event_id for event in self._status_events):
                raise RightsRejection("rights_status_event_replay")
            event = RightsStatusEvent(
                status_event_id=event_id,
                rights_record_id=rights_record_id,
                prior_status=prior,
                status=status,
                available_at=available_at,
            )
            self._status_events.append(event)
            return event

    def evaluate_fixture(
        self,
        fixture_id: str,
        *,
        boundary: UseBoundary | None = None,
        mutation: str | None = None,
    ) -> RightsDecision:
        selected = boundary or UseBoundary.INGEST
        record = self.current_rights_record()
        request = self.default_request(
            boundary=selected,
            evidence_sha256="94" * 32,
        )
        rights_record_id: str | None = record.rights_record_id
        if fixture_id == "rights-use-request-ambient-external":
            request = replace(
                request,
                boundary=UseBoundary.PROMPT,
                processing_boundary="external_model",
                destination="external_model",
                transmission="external_model",
            )
        if mutation == "missing_record":
            rights_record_id = None
        elif mutation == "missing_dimension":
            return self._deny(request, record, "rights_record_incomplete")
        elif mutation in {"expired", "revoked", "unknown"}:
            return self._deny(request, record, f"rights_{mutation}")
        elif mutation == "unresolved_counsel":
            return self._deny(request, record, "unresolved_counsel_question")
        elif mutation == "public_without_agreement":
            request = replace(request, acquisition_method="public_viewable")
        elif mutation == "undocumented_without_agreement":
            request = replace(request, acquisition_method="undocumented_endpoint")
        elif mutation in {
            "agreed_public_viewable",
            "agreed_undocumented_endpoint",
        }:
            request = replace(
                request,
                acquisition_method=mutation.removeprefix("agreed_"),
            )
        elif mutation and mutation.startswith("incompatible_"):
            request = _mutated_request(request, mutation.removeprefix("incompatible_"))
        return self.evaluate(request, rights_record_id=rights_record_id)

    def default_request(
        self,
        *,
        boundary: UseBoundary,
        evidence_sha256: str,
        processing_boundary: str = "local_only",
        destination: str = "local_owner_system",
        purpose: str | None = None,
        acquisition_method: str = "owner_download",
    ) -> UseRequest:
        with self._lock:
            self._counter += 1
            nonce = self._counter
        return UseRequest(
            subject_sha256=_hash(evidence_sha256, "rights_request_malformed"),
            evidence_sha256=_hash(evidence_sha256, "rights_request_malformed"),
            boundary=boundary,
            purpose=purpose or f"evidence_{boundary.value}",
            territory="US",
            display="owner_private",
            storage="retained_local",
            derivation="permitted",
            training="permitted",
            transmission=("external_model" if processing_boundary == "external_model" else "local_only"),
            backup="encrypted_local",
            attribution="required",
            retention="contract_term",
            deletion="rights_aware",
            audit="required",
            termination="enforce",
            acquisition_method=acquisition_method,
            processing_boundary=processing_boundary,
            destination=destination,
            requested_at=_format_time(self._clock()),
            nonce=nonce,
        )

    def evaluate(
        self,
        request: UseRequest,
        *,
        rights_record_id: str | None = None,
    ) -> RightsDecision:
        with self._lock:
            if rights_record_id is None:
                return self._deny(request, None, "rights_record_missing")
            record = next(
                (
                    item for item in self._rights_records
                    if item.rights_record_id == rights_record_id
                ),
                None,
            )
            if record is None:
                return self._deny(request, None, "rights_record_missing")
            status = self.current_status(record.rights_record_id)
            if status != "active":
                code = {
                    "expired": "rights_expired",
                    "revoked": "rights_revoked",
                    "terminated": "rights_terminated",
                    "superseded": "rights_superseded",
                    "unknown": "rights_unknown",
                }.get(status, "rights_unknown")
                return self._deny(request, record, code)
            at = _parse_time(request.requested_at)
            if at < _parse_time(record.effective_from):
                return self._deny(request, record, "rights_not_yet_effective")
            if record.effective_to is not None and at >= _parse_time(record.effective_to):
                return self._deny(request, record, "rights_expired")
            if self.applicable_unresolved_counsel_ids:
                return self._deny(request, record, "unresolved_counsel_question")
            legal = next(
                (
                    item for item in self._legal_terms
                    if item.legal_terms_id == record.legal_terms_id
                ),
                None,
            )
            if legal is None or legal.status != "active":
                return self._deny(request, record, "legal_terms_unavailable")
            if request.acquisition_method in {
                AcquisitionMethod.PUBLIC_VIEWABLE.value,
                AcquisitionMethod.UNDOCUMENTED_ENDPOINT.value,
            } and legal.automation_grant != "exact_recorded_automation":
                return self._deny(request, record, "acquisition_not_authorized")
            if (
                request.processing_boundary == "external_model"
                or request.destination == "external_model"
            ) and (
                request.processing_boundary,
                request.destination,
            ) not in record.processing_destinations:
                return self._deny(
                    request, record, "external_transmission_not_authorized"
                )
            if not record.boundary_permitted(request.boundary):
                return self._deny(request, record, "rights_incompatible")
            mismatch = _first_policy_mismatch(record, request)
            if mismatch is not None:
                code = (
                    "external_transmission_not_authorized"
                    if mismatch in {"transmission", "processing_destinations"}
                    else "rights_incompatible"
                )
                return self._deny(request, record, code)
            decision = self._decision(request, record, "permit", "terms_and_rights_match")
            self._permits.append(decision)
            self._decisions[decision.decision_id] = decision
            return decision

    def decision(self, decision_id: str) -> RightsDecision:
        try:
            return self._decisions[decision_id]
        except KeyError as error:
            raise RightsRejection("rights_decision_unknown") from error

    def record_policy_denial(
        self,
        request: UseRequest,
        *,
        rights_record_id: str,
        code: str,
    ) -> RightsDecision:
        if not (
            code.startswith("quarantine_")
            or code in {
                "identity_unresolved",
                "evidence_unavailable",
                "reproducibility_unverified",
            }
        ):
            raise RightsRejection("rights_denial_code_unknown")
        record = next(
            (
                item for item in self._rights_records
                if item.rights_record_id == rights_record_id
            ),
            None,
        )
        return self._deny(request, record, code)

    def with_exact_acquisition_agreement(
        self,
        acquisition_method: str,
    ) -> "RightsEvaluator":
        method = AcquisitionMethod(acquisition_method)
        if method not in {
            AcquisitionMethod.PUBLIC_VIEWABLE,
            AcquisitionMethod.UNDOCUMENTED_ENDPOINT,
        }:
            raise RightsRejection("acquisition_method_unknown")
        current = self.current_rights_record()
        expanded = replace(
            current,
            acquisition_methods=tuple(
                sorted({*current.acquisition_methods, method.value})
            ),
        )
        legal = tuple(
            replace(item, automation_grant="exact_recorded_automation")
            if item.legal_terms_id == current.legal_terms_id
            and item.authority_class is LegalAuthorityClass.PROVIDER_CONTRACT
            else item
            for item in self._legal_terms
        )
        return RightsEvaluator(
            rights_records=tuple(
                expanded if item.rights_record_id == current.rights_record_id else item
                for item in self._rights_records
            ),
            legal_terms=legal,
            clock=self._clock,
        )

    def replay_decision(
        self,
        decision: RightsDecision,
        *,
        boundary: UseBoundary,
    ) -> RightsDecision:
        if decision.boundary is not boundary:
            request = self.default_request(
                boundary=boundary,
                evidence_sha256=decision.evidence_sha256,
            )
            return self._deny(request, self.current_rights_record(), "rights_decision_boundary_mismatch")
        raise RightsRejection("rights_decision_replay", decision_id=decision.decision_id)

    def assert_promotion_eligible(
        self,
        *,
        quarantine: Sequence[str],
        rights_status: str = "active",
        identity_resolved: bool = True,
        available: bool = True,
        reproducible: bool = True,
        manual_override: bool = False,
    ) -> QuarantineDisposition:
        del manual_override  # No caller value can override a derived disposition.
        classes = tuple(sorted({QuarantineClass(item) for item in quarantine}, key=lambda item: item.value))
        if rights_status != "active":
            raise RightsRejection("quarantine_revoked_rights")
        if not identity_resolved:
            raise RightsRejection("quarantine_unresolved_identity")
        if not available:
            raise RightsRejection("quarantine_stale")
        if not reproducible:
            raise RightsRejection("quarantine_contaminated")
        if classes:
            raise RightsRejection(f"quarantine_{classes[0].value}")
        return QuarantineDisposition(
            eligible=True,
            classes=(),
            rights_record_id=self.current_rights_record().rights_record_id,
            evaluated_at=_format_time(self._clock()),
        )

    def logical_snapshot(self) -> RightsEvaluatorSnapshot:
        protected = tuple(
            sorted(
                [record.rights_record_id for record in self._rights_records]
                + [item.legal_terms_id for item in self._legal_terms]
                + [event.status_event_id for event in self._status_events]
                + [decision.decision_id for decision in self._permits]
            )
        )
        return RightsEvaluatorSnapshot(
            protected_relations=protected,
            raw_objects=0,
            canonical_events=0,
            redacted_denials=len(self._denials),
            permit_decisions=len(self._permits),
            status_events=len(self._status_events),
        )

    def _decision(
        self,
        request: UseRequest,
        record: RightsRecord | None,
        disposition: str,
        reason_code: str,
    ) -> RightsDecision:
        request_value = _request_value(request)
        request_id = sha256_hex(canonicalize(request_value))
        legal_terms_id = record.legal_terms_id if record is not None else _HASH_ZERO
        rights_record_id = record.rights_record_id if record is not None else _HASH_ZERO
        body = {
            **request_value,
            "request_id": request_id,
            "legal_terms_id": legal_terms_id,
            "rights_record_id": rights_record_id,
            "evaluator_version": EVALUATOR_VERSION,
            "disposition": disposition,
            "reason_code": reason_code,
            "decided_at": request.requested_at,
        }
        decision_id = sha256_hex(canonicalize(body))
        return RightsDecision(
            decision_id=decision_id,
            request_id=request_id,
            subject_sha256=request.subject_sha256,
            evidence_sha256=request.evidence_sha256,
            rights_record_id=rights_record_id,
            legal_terms_id=legal_terms_id,
            boundary=request.boundary,
            purpose=request.purpose,
            territory=request.territory,
            display=request.display,
            storage=request.storage,
            derivation=request.derivation,
            training=request.training,
            transmission=request.transmission,
            backup=request.backup,
            attribution=request.attribution,
            retention=request.retention,
            deletion=request.deletion,
            audit=request.audit,
            termination=request.termination,
            acquisition_method=request.acquisition_method,
            processing_boundary=request.processing_boundary,
            destination=request.destination,
            evaluator_version=EVALUATOR_VERSION,
            decided_at=request.requested_at,
            disposition=disposition,
            reason_code=reason_code,
        )

    def _deny(
        self,
        request: UseRequest,
        record: RightsRecord | None,
        code: str,
    ) -> RightsDecision:
        decision = self._decision(request, record, "deny", code)
        self._denials.append((decision.decision_id, request.boundary.value, code))
        self._decisions[decision.decision_id] = decision
        raise RightsRejection(code, decision_id=decision.decision_id)

    def _validate_registers(self) -> None:
        record_ids: set[str] = set()
        versions: set[tuple[str, int]] = set()
        legal_ids = {item.legal_terms_id for item in self._legal_terms}
        for record in self._rights_records:
            if record.rights_record_id in record_ids:
                raise RightsRejection("rights_record_replay")
            if (record.legal_terms_id, record.version) in versions:
                raise RightsRejection("rights_version_ambiguous")
            if record.legal_terms_id not in legal_ids:
                raise RightsRejection("legal_terms_unavailable")
            record_ids.add(record.rights_record_id)
            versions.add((record.legal_terms_id, record.version))


def _complete_fixture_policy(
    *,
    rights_record_id: str,
    legal_terms_id: str,
    status: str,
    effective_from: str,
    effective_to: Any,
    boundaries: Mapping[str, bool],
) -> dict[str, Any]:
    return {
        "rights_record_id": rights_record_id,
        "legal_terms_id": legal_terms_id,
        "version": 1,
        "status": status,
        "effective_from": effective_from,
        "effective_to": effective_to,
        "supersedes_rights_record_id": None,
        "boundaries": dict(boundaries),
        "purposes": [f"evidence_{boundary.value}" for boundary in UseBoundary],
        "territories": ["US"],
        "display": ["owner_private"],
        "storage": ["retained_local"],
        "derivation": ["permitted"],
        "training": ["permitted"],
        "transmission": ["local_only"],
        "backup": ["encrypted_local"],
        "attribution": ["required"],
        "retention": ["contract_term"],
        "deletion": ["rights_aware"],
        "audit": ["required"],
        "termination": ["enforce"],
        "acquisition_methods": [
            "documented_api", "licensed_file", "owner_download", "provided_fixture"
        ],
        "processing_destinations": [
            ["approved_local_boundary", "approved_local_model"],
            ["local_only", "backup_repository"],
            ["local_only", "export_recipient"],
            ["local_only", "local_owner_system"],
        ],
    }


def _first_policy_mismatch(record: RightsRecord, request: UseRequest) -> str | None:
    comparisons = (
        ("purposes", request.purpose),
        ("territories", request.territory),
        ("display", request.display),
        ("storage", request.storage),
        ("derivation", request.derivation),
        ("training", request.training),
        ("transmission", request.transmission),
        ("backup", request.backup),
        ("attribution", request.attribution),
        ("retention", request.retention),
        ("deletion", request.deletion),
        ("audit", request.audit),
        ("termination", request.termination),
        ("acquisition_methods", request.acquisition_method),
    )
    for name, requested in comparisons:
        if requested not in getattr(record, name):
            return name
    if (request.processing_boundary, request.destination) not in record.processing_destinations:
        return "processing_destinations"
    return None


def _mutated_request(request: UseRequest, dimension: str) -> UseRequest:
    if dimension == "purpose":
        return replace(request, purpose="ungranted_purpose")
    if dimension == "territory":
        return replace(request, territory="ZZ")
    if dimension == "display":
        return replace(request, display="public_display")
    if dimension == "storage":
        return replace(request, storage="external_storage")
    if dimension == "derivation":
        return replace(request, derivation="unrestricted")
    if dimension == "training":
        return replace(request, training="foundation_training")
    if dimension == "transmission":
        return replace(request, transmission="external_model")
    if dimension == "backup":
        return replace(request, backup="uncontrolled_backup")
    if dimension == "attribution":
        return replace(request, attribution="omitted")
    if dimension == "retention":
        return replace(request, retention="indefinite")
    if dimension == "deletion":
        return replace(request, deletion="caller_override")
    if dimension == "audit":
        return replace(request, audit="disabled")
    if dimension == "termination":
        return replace(request, termination="ignored")
    if dimension == "acquisition":
        return replace(request, acquisition_method="ungranted_acquisition")
    if dimension == "processing_destination":
        return replace(
            request,
            processing_boundary="external_model",
            destination="external_model",
            transmission="external_model",
        )
    raise RightsRejection("rights_request_malformed")


def _request_value(request: UseRequest) -> dict[str, Any]:
    return {
        "subject_sha256": request.subject_sha256,
        "evidence_sha256": request.evidence_sha256,
        "boundary": request.boundary.value,
        "purpose": request.purpose,
        "territory": request.territory,
        "display": request.display,
        "storage": request.storage,
        "derivation": request.derivation,
        "training": request.training,
        "transmission": request.transmission,
        "backup": request.backup,
        "attribution": request.attribution,
        "retention": request.retention,
        "deletion": request.deletion,
        "audit": request.audit,
        "termination": request.termination,
        "acquisition_method": request.acquisition_method,
        "processing_boundary": request.processing_boundary,
        "destination": request.destination,
        "requested_at": request.requested_at,
        "nonce": request.nonce,
    }


def _payload(record: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if record is None:
        return {}
    payload = record.get("payload")
    return payload if isinstance(payload, Mapping) else {}


def _digest(domain: str, *parts: str) -> str:
    return sha256_hex(
        domain.encode("ascii") + b"\0" + b"\0".join(part.encode("utf-8") for part in parts)
    )


def _hash(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RightsRejection(code)
    return value


def _timestamp_text(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise RightsRejection(code)
    _parse_time(value, code)
    return value


def _parse_time(value: str, code: str = "rights_request_malformed") -> datetime:
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except (TypeError, ValueError) as error:
        raise RightsRejection(code) from error
    if parsed.tzinfo != UTC:
        raise RightsRejection(code)
    return parsed


def _format_time(value: datetime) -> str:
    if value.tzinfo != UTC:
        raise RightsRejection("rights_clock_not_utc")
    return value.isoformat().replace("+00:00", "Z")
