"""Encounter accounting for Phase 12 memory metabolism (MEM-13).

``EncounterAccountant`` is the sole disposition author over the 12-06
substrate: every admitted encounter identity registered with the accountant
resolves to exactly one terminal disposition (``resident_capsule``,
``compressed_concept``, ``compressed_procedure``, ``statistical_residue``,
``audited_erasure``) or to an append-only ``disposition_deferred`` record
carrying a closed typed :class:`~.metabolism_types.DeferralReason`.

Boundary discipline:

* Exactly-one is enforced twice: the accountant rejects a second terminal
  disposition with ``encounter_already_disposed`` before the store's own
  ``encounter_disposition_exists`` backstop (partial-unique index plus
  in-transaction precheck) can fire.
* ``audited_erasure`` is a join to existing Phase 7 owner authority, never a
  new power: the caller supplies an authenticated
  :class:`ErasureDecisionLookup` and the accountant validates the decision
  identity's format and presence through it before any append.  A missing or
  unknown decision identity rejects ``erasure_decision_unknown``; a lookup
  fault rejects fail-closed.  The accountant deletes no bytes and exposes no
  deletion-command surface.
* Every terminal disposition that admits bytes is accounted into one quota
  event bound to the disposition identity, under the store's fixed per-tier
  ceilings; deferral admits no bytes and emits none.
* All writes flow through :class:`~.metabolism_store.MetabolismStore` under
  the accountant's bound fence; stale-fence, generation, and writer
  mismatches reject at the sole writer with the store's typed codes.

Determinism: no wall clock is read (``recorded_at`` is caller-provided
canonical UTC text), operation identities are content-derived, and the
replay/report surface reads only the accountant's own store tables in
sorted-identity order.  Every rejection carries a stable snake_case code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from types import MappingProxyType
from typing import Iterable, Protocol, runtime_checkable

from .canonical import canonicalize
from .metabolism_store import (
    DispositionAppend,
    MetabolismStore,
    OperationReceipt,
    QUOTA_TIER_CEILING_BYTES,
    QuotaEventAppend,
    metabolism_record_identity,
)
from .metabolism_types import (
    DISPOSITION_SCHEMA_VERSION,
    DeferralReason,
    DispositionKind,
    EncounterDisposition,
    NONE_SENTINEL,
    SAFE_INTEGER_MAX,
    compute_disposition_identity,
    disposition_from_raw,
)


ACCOUNTING_QUOTA_SCHEMA_VERSION = "skeleton.metabolism-accounting.quota-event.v1"
_OPERATION_DOMAIN = b"SKELETON_PHASE12_ACCOUNTING_OPERATION_V1"

# Closed binding from each terminal disposition kind to the quota tier and
# cause its bytes are accounted under (D-17).  ``disposition_deferred`` is
# deliberately absent: deferral leaves the capsule resident and admits no
# bytes, so no quota event may exist for it.
DISPOSITION_QUOTA_BINDING = MappingProxyType(
    {
        DispositionKind.RESIDENT_CAPSULE: ("hot", "admission"),
        DispositionKind.COMPRESSED_CONCEPT: ("warm", "compression"),
        DispositionKind.COMPRESSED_PROCEDURE: ("warm", "compression"),
        DispositionKind.STATISTICAL_RESIDUE: ("fossil", "residue_eviction"),
        DispositionKind.AUDITED_ERASURE: ("hot", "tombstone"),
    }
)


@dataclass(slots=True)
class MetabolismAccountingRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise MetabolismAccountingRejection(code)


@runtime_checkable
class ErasureDecisionLookup(Protocol):
    """Caller-supplied authenticated Phase 7 erasure-decision presence check.

    Implementations answer whether ``decision_id`` names an existing verified
    owner-authorized Phase 7 deletion or rights decision.  The accountant
    treats any exception or non-boolean answer as a fail-closed rejection;
    it never touches a filesystem or database to resolve the identity
    itself, so no ambient authority can stand in for the lookup.
    """

    def is_authorized_erasure_decision(self, decision_id: str) -> bool:
        """Return ``True`` only for a known verified erasure decision."""
        ...


def _identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _nonnegative(value: object, code: str) -> int:
    if type(value) is not int or value < 0:
        _reject(code)
    return value


def _utc(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) < 20 or not value.endswith("Z"):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise MetabolismAccountingRejection(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _reject(code)
    return value


def _operation_identity(kind: str, record_id: str) -> str:
    payload = canonicalize({"kind": kind, "record_id": record_id})
    return sha256(
        len(_OPERATION_DOMAIN).to_bytes(8, "big")
        + _OPERATION_DOMAIN
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class AccountedDisposition:
    """One committed disposition with its bound quota accounting, if any."""

    encounter_id: str
    disposition_id: str
    disposition: DispositionKind
    attempt_ordinal: int
    canonical_bytes: bytes
    disposition_receipt: OperationReceipt
    quota_event_id: str | None
    quota_receipt: OperationReceipt | None


class EncounterAccountant:
    """Exactly-one terminal disposition per encounter, or a typed deferral.

    The accountant is bound at construction to one store, one fence
    (``fence_id``/``generation``/``writer_id``), one cycle
    (``cycle_ordinal``/``cycle_input_root``), and one immutable encounter
    identity snapshot.  It holds no deletion, promotion, signing, or policy
    surface, and it mints no erasure authority: ``record_audited_erasure``
    only joins an existing Phase 7 decision identity verified through the
    supplied :class:`ErasureDecisionLookup`.
    """

    __slots__ = (
        "_attempts",
        "_cycle_input_root",
        "_cycle_ordinal",
        "_encounter_order",
        "_encounters",
        "_erasure_lookup",
        "_fence_id",
        "_generation",
        "_recorded_at",
        "_store",
        "_terminal",
        "_writer_id",
    )

    def __init__(
        self,
        store: MetabolismStore,
        *,
        writer_id: str,
        fence_id: str,
        generation: int,
        cycle_ordinal: int,
        cycle_input_root: str,
        encounter_ids: Iterable[str],
        erasure_lookup: ErasureDecisionLookup,
        recorded_at: str,
    ) -> None:
        if not isinstance(store, MetabolismStore):
            _reject("accounting_store_invalid")
        self._store = store
        self._writer_id = _identity(writer_id, "accounting_identity_invalid")
        self._fence_id = _identity(fence_id, "accounting_identity_invalid")
        self._generation = _nonnegative(generation, "accounting_cycle_invalid")
        self._cycle_ordinal = _nonnegative(cycle_ordinal, "accounting_cycle_invalid")
        self._cycle_input_root = _identity(
            cycle_input_root, "accounting_identity_invalid"
        )
        self._recorded_at = _utc(recorded_at, "accounting_recorded_at_invalid")
        if isinstance(encounter_ids, str):
            _reject("encounter_set_invalid")
        ordered = tuple(
            _identity(encounter_id, "encounter_identity_invalid")
            for encounter_id in encounter_ids
        )
        if len(ordered) != len(set(ordered)):
            _reject("encounter_set_invalid")
        self._encounter_order = tuple(sorted(ordered))
        self._encounters = frozenset(ordered)
        if not callable(
            getattr(erasure_lookup, "is_authorized_erasure_decision", None)
        ):
            _reject("erasure_lookup_invalid")
        self._erasure_lookup = erasure_lookup
        self._terminal: dict[str, str] = {}
        self._attempts: dict[str, int] = {}

    @property
    def encounter_ids(self) -> tuple[str, ...]:
        """The immutable sorted cycle-input encounter identity snapshot."""

        return self._encounter_order

    # -- disposition authoring -------------------------------------------

    def record_resident_capsule(
        self, encounter_id: str, *, capsule_id: str, byte_count: int
    ) -> AccountedDisposition:
        """Retain the encounter as a resident capsule and account its bytes."""

        return self._record_terminal(
            encounter_id,
            DispositionKind.RESIDENT_CAPSULE,
            references={
                "capsule_id": _identity(capsule_id, "disposition_reference_invalid")
            },
            byte_count=byte_count,
        )

    def record_compressed_concept(
        self,
        encounter_id: str,
        *,
        artifact_id: str,
        gate_receipt_id: str,
        byte_count: int,
    ) -> AccountedDisposition:
        """Dispose the encounter into a gate-receipted compressed concept."""

        return self._record_terminal(
            encounter_id,
            DispositionKind.COMPRESSED_CONCEPT,
            references={
                "artifact_id": _identity(
                    artifact_id, "disposition_reference_invalid"
                ),
                "gate_receipt_id": _identity(
                    gate_receipt_id, "disposition_reference_invalid"
                ),
            },
            byte_count=byte_count,
        )

    def record_compressed_procedure(
        self,
        encounter_id: str,
        *,
        artifact_id: str,
        gate_receipt_id: str,
        byte_count: int,
    ) -> AccountedDisposition:
        """Dispose the encounter into a gate-receipted compressed procedure."""

        return self._record_terminal(
            encounter_id,
            DispositionKind.COMPRESSED_PROCEDURE,
            references={
                "artifact_id": _identity(
                    artifact_id, "disposition_reference_invalid"
                ),
                "gate_receipt_id": _identity(
                    gate_receipt_id, "disposition_reference_invalid"
                ),
            },
            byte_count=byte_count,
        )

    def record_statistical_residue(
        self, encounter_id: str, *, residue_snapshot_id: str, byte_count: int
    ) -> AccountedDisposition:
        """Dispose the encounter into one bounded residue snapshot."""

        return self._record_terminal(
            encounter_id,
            DispositionKind.STATISTICAL_RESIDUE,
            references={
                "residue_snapshot_id": _identity(
                    residue_snapshot_id, "disposition_reference_invalid"
                )
            },
            byte_count=byte_count,
        )

    def record_audited_erasure(
        self, encounter_id: str, *, erasure_decision_id: str, byte_count: int
    ) -> AccountedDisposition:
        """Join an existing verified Phase 7 erasure decision (D-03).

        The decision identity must be well-formed and known to the supplied
        authenticated lookup before any row is appended; the accountant
        itself never deletes bytes and constructs no deletion command.
        """

        decision_id = _identity(erasure_decision_id, "erasure_decision_invalid")
        self._verify_erasure_decision(decision_id)
        return self._record_terminal(
            encounter_id,
            DispositionKind.AUDITED_ERASURE,
            references={"erasure_decision_id": decision_id},
            byte_count=byte_count,
        )

    def record_deferral(
        self, encounter_id: str, *, reason: DeferralReason | str
    ) -> AccountedDisposition:
        """Fail closed to resident retention with one closed typed reason."""

        try:
            typed_reason = DeferralReason(reason)
        except (TypeError, ValueError) as error:
            raise MetabolismAccountingRejection("deferral_reason_unknown") from error
        encounter = self._require_open_encounter(encounter_id)
        attempt_ordinal = self._attempts.get(encounter, 0) + 1
        raw, disposition_id = self._disposition_bytes(
            encounter,
            DispositionKind.DISPOSITION_DEFERRED,
            references={},
            deferral_reason=typed_reason.value,
            attempt_ordinal=attempt_ordinal,
        )
        receipt = self._store.append_disposition(
            DispositionAppend(raw, self._recorded_at),
            writer_id=self._writer_id,
            operation_id=_operation_identity("disposition", disposition_id),
        )
        self._attempts[encounter] = attempt_ordinal
        return AccountedDisposition(
            encounter_id=encounter,
            disposition_id=disposition_id,
            disposition=DispositionKind.DISPOSITION_DEFERRED,
            attempt_ordinal=attempt_ordinal,
            canonical_bytes=raw,
            disposition_receipt=receipt,
            quota_event_id=None,
            quota_receipt=None,
        )

    # -- replay / report --------------------------------------------------

    def dispositions_for_cycle(
        self, cycle_ordinal: int | None = None
    ) -> tuple[EncounterDisposition, ...]:
        """Byte-verified disposition ledger for one cycle, sorted by identity.

        Reads only the accountant's own store tables through the sole
        writer's replay surface; every returned value is re-authenticated
        from its stored canonical bytes.
        """

        selected = (
            self._cycle_ordinal
            if cycle_ordinal is None
            else _nonnegative(cycle_ordinal, "accounting_cycle_invalid")
        )
        return tuple(
            sorted(
                (
                    disposition
                    for disposition in self._stored_dispositions()
                    if disposition.cycle_ordinal == selected
                ),
                key=lambda item: (item.encounter_id, item.disposition_id),
            )
        )

    def undisposed_encounters(self) -> tuple[str, ...]:
        """Sorted snapshot encounters with zero terminal dispositions.

        Encounters holding only ``disposition_deferred`` records count as
        accounted-but-open and therefore still appear here; nothing is
        repaired silently.
        """

        terminal = {
            disposition.encounter_id
            for disposition in self._stored_dispositions()
            if disposition.terminal
        }
        return tuple(
            encounter_id
            for encounter_id in self._encounter_order
            if encounter_id not in terminal
        )

    # -- internals --------------------------------------------------------

    def _require_open_encounter(self, encounter_id: object) -> str:
        encounter = _identity(encounter_id, "encounter_identity_invalid")
        if encounter not in self._encounters:
            _reject("encounter_unknown")
        if encounter in self._terminal:
            _reject("encounter_already_disposed")
        return encounter

    def _verify_erasure_decision(self, decision_id: str) -> None:
        try:
            verdict = self._erasure_lookup.is_authorized_erasure_decision(
                decision_id
            )
        except MetabolismAccountingRejection:
            raise
        except Exception as error:
            raise MetabolismAccountingRejection(
                "erasure_decision_lookup_failed"
            ) from error
        if verdict is True:
            return
        if verdict is False:
            _reject("erasure_decision_unknown")
        _reject("erasure_decision_lookup_failed")

    def _record_terminal(
        self,
        encounter_id: object,
        kind: DispositionKind,
        *,
        references: dict[str, str],
        byte_count: object,
    ) -> AccountedDisposition:
        encounter = self._require_open_encounter(encounter_id)
        if type(byte_count) is not int or not 0 <= byte_count <= SAFE_INTEGER_MAX:
            _reject("byte_count_invalid")
        tier, cause = DISPOSITION_QUOTA_BINDING[kind]
        current_total = self._store.quota_totals().get(tier)
        ceiling = QUOTA_TIER_CEILING_BYTES.get(tier)
        if current_total is None or ceiling is None:
            _reject("accounting_quota_tier_unknown")
        if current_total + byte_count > ceiling:
            _reject("quota_ceiling_exceeded")

        attempt_ordinal = self._attempts.get(encounter, 0) + 1
        raw, disposition_id = self._disposition_bytes(
            encounter,
            kind,
            references=references,
            deferral_reason=NONE_SENTINEL,
            attempt_ordinal=attempt_ordinal,
        )
        receipt = self._store.append_disposition(
            DispositionAppend(raw, self._recorded_at),
            writer_id=self._writer_id,
            operation_id=_operation_identity("disposition", disposition_id),
        )
        self._attempts[encounter] = attempt_ordinal
        self._terminal[encounter] = disposition_id

        quota_raw = canonicalize(
            {
                "byte_delta": byte_count,
                "cause": cause,
                "cycle_ordinal": self._cycle_ordinal,
                "disposition_id": disposition_id,
                "encounter_id": encounter,
                "schema_version": ACCOUNTING_QUOTA_SCHEMA_VERSION,
                "tier": tier,
            }
        )
        quota_event_id = metabolism_record_identity("quota_event", quota_raw)
        quota_receipt = self._store.append_quota_event(
            QuotaEventAppend(
                quota_event_id,
                tier,
                cause,
                byte_count,
                self._fence_id,
                self._generation,
                attempt_ordinal,
                self._recorded_at,
                quota_raw,
            ),
            writer_id=self._writer_id,
            operation_id=_operation_identity("quota_event", quota_event_id),
        )
        return AccountedDisposition(
            encounter_id=encounter,
            disposition_id=disposition_id,
            disposition=kind,
            attempt_ordinal=attempt_ordinal,
            canonical_bytes=raw,
            disposition_receipt=receipt,
            quota_event_id=quota_event_id,
            quota_receipt=quota_receipt,
        )

    def _disposition_bytes(
        self,
        encounter_id: str,
        kind: DispositionKind,
        *,
        references: dict[str, str],
        deferral_reason: str,
        attempt_ordinal: int,
    ) -> tuple[bytes, str]:
        value: dict[str, object] = {
            "schema_version": DISPOSITION_SCHEMA_VERSION,
            "record_type": "encounter_disposition",
            "disposition_id": "0" * 64,
            "encounter_id": encounter_id,
            "cycle_ordinal": self._cycle_ordinal,
            "cycle_input_root": self._cycle_input_root,
            "fence_id": self._fence_id,
            "generation": self._generation,
            "attempt_ordinal": attempt_ordinal,
            "disposition": kind.value,
            "capsule_id": references.get("capsule_id", NONE_SENTINEL),
            "artifact_id": references.get("artifact_id", NONE_SENTINEL),
            "gate_receipt_id": references.get("gate_receipt_id", NONE_SENTINEL),
            "residue_snapshot_id": references.get(
                "residue_snapshot_id", NONE_SENTINEL
            ),
            "erasure_decision_id": references.get(
                "erasure_decision_id", NONE_SENTINEL
            ),
            "deferral_reason": deferral_reason,
        }
        disposition_id = compute_disposition_identity(value)
        value["disposition_id"] = disposition_id
        return canonicalize(value), disposition_id

    def _stored_dispositions(self) -> tuple[EncounterDisposition, ...]:
        return tuple(
            disposition_from_raw(raw)
            for table, _record_id, _declared, raw in self._store.replay_verify().records
            if table == "memory_dispositions"
        )


__all__ = [
    "ACCOUNTING_QUOTA_SCHEMA_VERSION",
    "AccountedDisposition",
    "DISPOSITION_QUOTA_BINDING",
    "EncounterAccountant",
    "ErasureDecisionLookup",
    "MetabolismAccountingRejection",
]
