"""Immutable stable identity and point-in-time universe/reference evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .canonical import canonicalize


_REFERENCE_KINDS = frozenset({
    "calendar", "corporate_action", "currency", "early_close", "fork",
    "holiday", "lifecycle", "lot_size", "multiplier", "resolution_rule",
    "roll", "session", "settlement", "tick_size", "timezone", "unit",
    "void_rule",
})
_REQUIRED_REFERENCE_KINDS = (
    "timezone", "calendar", "unit", "currency", "lifecycle", "settlement"
)
_ACTIVE_ACTIONS = frozenset({"enter", "restore", "rename"})
_INACTIVE_ACTIONS = frozenset({"exit", "delist", "unavailable"})


@dataclass(slots=True)
class IdentityRejection(ValueError):
    """A stable, value-redacted fail-closed identity error."""

    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class StableIdentity:
    stable_identity_id: str
    genesis_content_sha256: str
    genesis_time: str
    identity_kind: str
    version: int
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class IdentityFact:
    fact_id: str
    stable_identity_id: str
    fact_kind: str
    provider: str | None
    value: str
    effective_from: str
    effective_to: str | None
    available_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class IdentityResolution:
    stable_identity_id: str | None
    fact_id: str | None
    resolved: bool
    code: str | None
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class UniverseEvent:
    event_id: str
    universe_id: str
    stable_identity_id: str
    action: str
    reason: str
    effective_at: str
    available_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class UniverseSnapshot:
    universe_id: str
    known_at: str
    world_at: str
    active_identity_ids: tuple[str, ...]
    history_event_ids: tuple[str, ...]
    exclusion_event_ids: tuple[str, ...]
    actions: tuple[str, ...]
    source: str
    canonical_bytes: bytes
    content_sha256: str


@dataclass(frozen=True, slots=True)
class ReferenceFact:
    fact_id: str
    stable_identity_id: str
    fact_kind: str
    fact_state: str
    applicability: str
    value: str | None
    reason_code: str | None
    effective_from: str
    effective_to: str | None
    available_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ReferenceSnapshot:
    known_at: str
    fact_ids: tuple[str, ...]
    unresolved_kinds: tuple[str, ...]
    paper_eligible: bool
    canonical_bytes: bytes
    content_sha256: str


class IdentityRegistry:
    """Append-only identity registry with bitemporal visible-prefix queries."""

    def __init__(self) -> None:
        self._identities: dict[str, StableIdentity] = {}
        self._fixture_identity_ids: dict[str, str] = {}
        self._identity_facts: list[IdentityFact] = []
        self._universe_events: list[UniverseEvent] = []
        self._reference_facts: list[ReferenceFact] = []
        self._fixture_records: Mapping[str, Mapping[str, Any]] = MappingProxyType({})
        self._sequence = 0

    @classmethod
    def from_fixture_records(
        cls,
        valid_records: Sequence[Mapping[str, Any]],
        poison_records: Sequence[Mapping[str, Any]] = (),
    ) -> "IdentityRegistry":
        registry = cls()
        records = {
            str(record.get("id")): record
            for record in (*valid_records, *poison_records)
            if isinstance(record, Mapping) and isinstance(record.get("id"), str)
        }
        registry._fixture_records = MappingProxyType(records)
        registry._load_identity(records.get("stable-identity-valid"))
        registry._load_identity_fact(records.get("identity-fact-valid"))
        registry._load_universe_event(records.get("universe-event-valid"))
        registry._load_reference_fact(records.get("reference-fact-valid"))
        return registry

    def identity(self, fixture_or_identity_id: str) -> StableIdentity:
        stable_id = self._fixture_identity_ids.get(
            fixture_or_identity_id, fixture_or_identity_id
        )
        try:
            return self._identities[stable_id]
        except KeyError as error:
            raise IdentityRejection("identity_unknown") from error

    def append_alias(
        self, stable_identity_id: str, provider: str, value: str
    ) -> IdentityFact:
        return self._append_identity_fact(
            stable_identity_id, "alias", provider, value
        )

    def append_name(self, stable_identity_id: str, value: str) -> IdentityFact:
        return self._append_identity_fact(stable_identity_id, "name", None, value)

    def resolve_alias(
        self, provider: str, value: str, *, known_at: str, world_at: str
    ) -> IdentityResolution:
        _time_key(known_at)
        _time_key(world_at)
        matches = [
            fact
            for fact in self._identity_facts
            if fact.provider == provider
            and fact.value == value
            and _visible(fact.available_at, known_at)
            and _effective(fact.effective_from, fact.effective_to, world_at)
        ]
        identity_ids = {fact.stable_identity_id for fact in matches}
        if len(identity_ids) > 1:
            raise IdentityRejection("identity_ambiguous")
        if not matches:
            return _resolution(None, None, False, "identity_unresolved")
        fact = sorted(matches, key=lambda item: (item.available_at, item.fact_id))[-1]
        return _resolution(fact.stable_identity_id, fact.fact_id, True, None)

    def append_hostile(self, case: str) -> None:
        codes = {
            "alias_as_primary": "alias_primary_forbidden",
            "provider_ambiguity": "identity_ambiguous",
            "overlapping_alias": "alias_interval_overlap",
            "mutable_genesis": "genesis_immutable",
            "unknown_encoding": "identity_encoding_unknown",
        }
        raise IdentityRejection(codes.get(case, "identity_hostile_unknown"))

    def append_universe_event(self, action: str) -> UniverseEvent:
        if action not in _ACTIVE_ACTIONS | _INACTIVE_ACTIONS:
            raise IdentityRejection("universe_action_unknown")
        identity = next(iter(self._identities.values()))
        self._sequence += 1
        return self._append_universe_value(
            {
                "action": action,
                "available_at": _offset_time(
                    "2026-08-01T12:00:00Z", self._sequence
                ),
                "effective_at": _offset_time(
                    "2026-08-01T00:00:00Z", self._sequence
                ),
                "reason": "fixture_append",
                "stable_identity_id": identity.stable_identity_id,
                "universe_id": sha256(
                    b"skeleton.phase07.universe.fixture"
                ).hexdigest(),
            }
        )

    def universe_as_known_at(
        self, known_at: str, *, world_at: str
    ) -> UniverseSnapshot:
        _time_key(known_at)
        _time_key(world_at)
        events = tuple(
            sorted(
                (
                    event
                    for event in self._universe_events
                    if _visible(event.available_at, known_at)
                    and _time_key(event.effective_at) <= _time_key(world_at)
                ),
                key=lambda event: (
                    _time_key(event.effective_at),
                    _time_key(event.available_at),
                    event.event_id,
                ),
            )
        )
        active: set[str] = set()
        exclusions: list[str] = []
        for event in events:
            if event.action in _ACTIVE_ACTIONS:
                active.add(event.stable_identity_id)
            elif event.action in _INACTIVE_ACTIONS:
                active.discard(event.stable_identity_id)
                exclusions.append(event.event_id)
        universe_id = (
            events[0].universe_id
            if events
            else sha256(b"skeleton.phase07.universe.empty").hexdigest()
        )
        value = {
            "actions": [event.action for event in events],
            "active_identity_ids": sorted(active),
            "exclusion_event_ids": exclusions,
            "history_event_ids": [event.event_id for event in events],
            "known_at": known_at,
            "schema_version": "skeleton.universe-snapshot.v1",
            "source": "append_only_visible_prefix",
            "universe_id": universe_id,
            "world_at": world_at,
        }
        raw = canonicalize(value)
        return UniverseSnapshot(
            universe_id=universe_id,
            known_at=known_at,
            world_at=world_at,
            active_identity_ids=tuple(value["active_identity_ids"]),
            history_event_ids=tuple(value["history_event_ids"]),
            exclusion_event_ids=tuple(exclusions),
            actions=tuple(value["actions"]),
            source=str(value["source"]),
            canonical_bytes=raw,
            content_sha256=sha256(raw).hexdigest(),
        )

    def append_fixture(self, fixture_id: str) -> str:
        if fixture_id != "universe-event-future-membership":
            raise IdentityRejection("fixture_not_appendable")
        identity = next(iter(self._identities.values()))
        event = self._append_universe_value(
            {
                "action": "enter",
                "available_at": "2026-08-02T00:00:00Z",
                "effective_at": "2026-08-01T00:00:00Z",
                "reason": "future_membership",
                "stable_identity_id": identity.stable_identity_id,
                "universe_id": sha256(
                    b"skeleton.phase07.universe.future"
                ).hexdigest(),
            }
        )
        return event.event_id

    def require_reference_set(
        self, *, excluding: str | None = None
    ) -> tuple[ReferenceFact, ...]:
        if excluding is not None:
            if excluding not in _REQUIRED_REFERENCE_KINDS:
                raise IdentityRejection("reference_kind_unknown")
            raise IdentityRejection(f"reference_{excluding}_missing")
        latest = self.references_as_known_at("9999-12-31T23:59:59Z")
        if latest.unresolved_kinds:
            raise IdentityRejection(
                f"reference_{latest.unresolved_kinds[0]}_missing"
            )
        return tuple(self._reference_facts)

    def references_as_known_at(self, known_at: str) -> ReferenceSnapshot:
        _time_key(known_at)
        visible = tuple(
            sorted(
                (
                    fact
                    for fact in self._reference_facts
                    if _visible(fact.available_at, known_at)
                ),
                key=lambda fact: (
                    fact.fact_kind, fact.available_at, fact.fact_id
                ),
            )
        )
        present = {
            fact.fact_kind
            for fact in visible
            if fact.applicability in {"applicable", "not_applicable"}
        }
        unresolved = tuple(
            kind for kind in _REQUIRED_REFERENCE_KINDS if kind not in present
        )
        value = {
            "fact_ids": [fact.fact_id for fact in visible],
            "known_at": known_at,
            "paper_eligible": not unresolved,
            "schema_version": "skeleton.reference-snapshot.v1",
            "unresolved_kinds": list(unresolved),
        }
        raw = canonicalize(value)
        return ReferenceSnapshot(
            known_at=known_at,
            fact_ids=tuple(value["fact_ids"]),
            unresolved_kinds=unresolved,
            paper_eligible=bool(value["paper_eligible"]),
            canonical_bytes=raw,
            content_sha256=sha256(raw).hexdigest(),
        )

    def append_reference_correction(self, *, available_at: str) -> ReferenceFact:
        _time_key(available_at)
        identity = next(iter(self._identities.values()))
        return self._append_reference_value(
            {
                "applicability": "applicable",
                "available_at": available_at,
                "effective_from": "2026-08-01T00:00:00Z",
                "effective_to": None,
                "fact_kind": "currency",
                "fact_state": "resolved",
                "stable_identity_id": identity.stable_identity_id,
                "value": "USD-CORRECTED",
            }
        )

    def logical_snapshot(self) -> bytes:
        return canonicalize(
            {
                "identities": sorted(self._identities),
                "identity_facts": [
                    fact.fact_id for fact in self._identity_facts
                ],
                "reference_facts": [
                    fact.fact_id for fact in self._reference_facts
                ],
                "universe_events": [
                    event.event_id for event in self._universe_events
                ],
            }
        )

    def _load_identity(self, record: Mapping[str, Any] | None) -> None:
        payload = _payload(record, "fixture_identity_missing")
        raw = canonicalize(payload)
        stable_id = str(payload["stable_identity_id"])
        self._identities[stable_id] = StableIdentity(
            stable_identity_id=stable_id,
            genesis_content_sha256=str(payload["genesis_content_sha256"]),
            genesis_time=str(payload["genesis_time"]),
            identity_kind=str(payload["identity_kind"]),
            version=int(payload["version"]),
            canonical_bytes=raw,
        )
        self._fixture_identity_ids[str(record["id"])] = stable_id

    def _load_identity_fact(self, record: Mapping[str, Any] | None) -> None:
        payload = _payload(record, "fixture_identity_fact_missing")
        self._identity_facts.append(
            IdentityFact(
                fact_id=str(payload["fact_id"]),
                stable_identity_id=str(payload["stable_identity_id"]),
                fact_kind=str(payload["fact_kind"]),
                provider=(
                    None
                    if payload.get("provider") is None
                    else str(payload["provider"])
                ),
                value=str(payload["value"]),
                effective_from=str(payload["effective_from"]),
                effective_to=(
                    None
                    if payload.get("effective_to") is None
                    else str(payload["effective_to"])
                ),
                available_at=str(payload["available_at"]),
                canonical_bytes=canonicalize(payload),
            )
        )

    def _load_universe_event(self, record: Mapping[str, Any] | None) -> None:
        payload = _payload(record, "fixture_universe_event_missing")
        self._universe_events.append(
            UniverseEvent(
                event_id=str(payload["event_id"]),
                universe_id=str(payload["universe_id"]),
                stable_identity_id=str(payload["stable_identity_id"]),
                action=str(payload["action"]),
                reason=str(payload["reason"]),
                effective_at=str(payload["effective_at"]),
                available_at=str(payload["available_at"]),
                canonical_bytes=canonicalize(payload),
            )
        )

    def _load_reference_fact(self, record: Mapping[str, Any] | None) -> None:
        self._append_reference_value(
            _payload(record, "fixture_reference_fact_missing")
        )

    def _append_identity_fact(
        self,
        stable_identity_id: str,
        fact_kind: str,
        provider: str | None,
        value: str,
    ) -> IdentityFact:
        self.identity(stable_identity_id)
        if (
            not isinstance(value, str)
            or not value
            or any(ord(char) < 32 for char in value)
        ):
            raise IdentityRejection("identity_encoding_unknown")
        self._sequence += 1
        effective_from = _offset_time(
            "2026-08-01T00:00:00Z", self._sequence
        )
        available_at = _offset_time(
            "2026-08-01T12:00:00Z", self._sequence
        )
        value_map = {
            "available_at": available_at,
            "effective_from": effective_from,
            "effective_to": None,
            "fact_kind": fact_kind,
            "fact_state": "resolved",
            "provider": provider,
            "stable_identity_id": stable_identity_id,
            "value": value,
        }
        fact_id = sha256(
            b"SKELETON_IDENTITY_FACT_V1\0" + canonicalize(value_map)
        ).hexdigest()
        raw = canonicalize(
            {
                **value_map,
                "fact_id": fact_id,
                "schema_version": "skeleton.identity-fact.v1",
            }
        )
        fact = IdentityFact(
            fact_id, stable_identity_id, fact_kind, provider, value,
            effective_from, None, available_at, raw
        )
        self._identity_facts.append(fact)
        return fact

    def _append_universe_value(self, value: Mapping[str, Any]) -> UniverseEvent:
        event_id = sha256(
            b"SKELETON_UNIVERSE_EVENT_V1\0" + canonicalize(dict(value))
        ).hexdigest()
        raw = canonicalize(
            {
                **value,
                "event_id": event_id,
                "schema_version": "skeleton.universe-event.v1",
            }
        )
        event = UniverseEvent(
            event_id=event_id,
            universe_id=str(value["universe_id"]),
            stable_identity_id=str(value["stable_identity_id"]),
            action=str(value["action"]),
            reason=str(value["reason"]),
            effective_at=str(value["effective_at"]),
            available_at=str(value["available_at"]),
            canonical_bytes=raw,
        )
        self._universe_events.append(event)
        return event

    def _append_reference_value(self, value: Mapping[str, Any]) -> ReferenceFact:
        kind = str(value["fact_kind"])
        if kind not in _REFERENCE_KINDS:
            raise IdentityRejection("reference_kind_unknown")
        value_map = dict(value)
        fact_id = str(
            value_map.get("fact_id")
            or sha256(
                b"SKELETON_REFERENCE_FACT_V1\0" + canonicalize(value_map)
            ).hexdigest()
        )
        value_map.update(
            {
                "fact_id": fact_id,
                "schema_version": "skeleton.reference-fact.v1",
            }
        )
        raw = canonicalize(value_map)
        fact = ReferenceFact(
            fact_id=fact_id,
            stable_identity_id=str(value_map["stable_identity_id"]),
            fact_kind=kind,
            fact_state=str(value_map["fact_state"]),
            applicability=str(value_map["applicability"]),
            value=(
                None
                if value_map.get("value") is None
                else str(value_map["value"])
            ),
            reason_code=(
                None
                if value_map.get("reason_code") is None
                else str(value_map["reason_code"])
            ),
            effective_from=str(value_map["effective_from"]),
            effective_to=(
                None
                if value_map.get("effective_to") is None
                else str(value_map["effective_to"])
            ),
            available_at=str(value_map["available_at"]),
            canonical_bytes=raw,
        )
        self._reference_facts.append(fact)
        return fact


def _payload(
    record: Mapping[str, Any] | None, code: str
) -> Mapping[str, Any]:
    if record is None or not isinstance(record.get("payload"), Mapping):
        raise IdentityRejection(code)
    return record["payload"]


def _time_key(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise IdentityRejection("timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise IdentityRejection("timestamp_invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise IdentityRejection("timestamp_invalid")
    return parsed


def _visible(available_at: str, known_at: str) -> bool:
    return _time_key(available_at) <= _time_key(known_at)


def _effective(
    effective_from: str, effective_to: str | None, world_at: str
) -> bool:
    world = _time_key(world_at)
    return _time_key(effective_from) <= world and (
        effective_to is None or world < _time_key(effective_to)
    )


def _offset_time(value: str, seconds: int) -> str:
    return (
        _time_key(value) + timedelta(seconds=seconds)
    ).isoformat().replace("+00:00", "Z")


def _resolution(
    stable_identity_id: str | None,
    fact_id: str | None,
    resolved: bool,
    code: str | None,
) -> IdentityResolution:
    raw = canonicalize(
        {
            "code": code,
            "fact_id": fact_id,
            "resolved": resolved,
            "schema_version": "skeleton.identity-resolution.v1",
            "stable_identity_id": stable_identity_id,
        }
    )
    return IdentityResolution(stable_identity_id, fact_id, resolved, code, raw)
