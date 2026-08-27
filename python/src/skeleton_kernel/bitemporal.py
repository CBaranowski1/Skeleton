"""Append-only bitemporal canonical-event queries over the Phase 7 sole writer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import re
import sqlite3
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .canonical import canonicalize
from .evidence_migrations import EvidenceMigrations
from .evidence_store import EvidenceStore


_TIMESTAMP = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})?Z$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BASE_EVENT_ID = "1" * 64
_CORRECTION_EVENT_ID = "c1" * 32
_LEGAL_TERMS_ID = sha256(b"skeleton.bitemporal.fixture.legal").hexdigest()
_KNOWN_TIMEZONE = "utc"
_KNOWN_CALENDAR = "gregorian"
_KNOWN_UNIT = "share"
_KNOWN_CURRENCY = "usd"


@dataclass(slots=True)
class BitemporalRejection(ValueError):
    """Stable fail-closed rejection without submitted evidence values."""

    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class KnowledgeTime:
    """Normalized UTC boundary describing what was available to the organism."""

    value: str

    def __post_init__(self) -> None:
        _timestamp_key(self.value)


@dataclass(frozen=True, slots=True)
class WorldTime:
    """Normalized UTC boundary describing modeled effective world state."""

    value: str

    def __post_init__(self) -> None:
        _timestamp_key(self.value)


@dataclass(frozen=True, slots=True)
class CanonicalEventView:
    """One immutable resolved canonical event."""

    event_id: str
    source_time: str
    available_at: str
    effective_at: str
    stable_identity_id: str
    sequence: int
    correction_of: str | None
    quality: str
    canonical_bytes: bytes

    def as_value(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "available_at": self.available_at,
                "correction_of": self.correction_of,
                "effective_at": self.effective_at,
                "event_id": self.event_id,
                "quality": self.quality,
                "sequence": self.sequence,
                "source_time": self.source_time,
                "stable_identity_id": self.stable_identity_id,
            }
        )


@dataclass(frozen=True, slots=True)
class UnresolvedEventView:
    """Visible evidence that cannot be safely ordered or made paper eligible."""

    event_id: str
    code: str

    def as_value(self) -> Mapping[str, str]:
        return MappingProxyType({"code": self.code, "event_id": self.event_id})


@dataclass(frozen=True, slots=True)
class BitemporalSnapshot:
    """Canonical immutable result for one world/knowledge-time query."""

    known_at: KnowledgeTime
    world_at: WorldTime
    events: tuple[CanonicalEventView, ...]
    unresolved: tuple[UnresolvedEventView, ...]
    canonical_bytes: bytes
    content_sha256: str
    known_empty: bool
    paper_eligible: bool

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(event.event_id for event in self.events)


class BitemporalService:
    """Resolve visible-prefix truth using only an injected Phase 7 connection."""

    def __init__(
        self,
        store: EvidenceStore,
        *,
        fixture_records: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        if not isinstance(store, EvidenceStore):
            raise BitemporalRejection("writer_connection_required")
        self.evidence_store = store
        self.connection = store.connection
        self._fixture_records = MappingProxyType(dict(fixture_records or {}))

    @classmethod
    def from_fixture_records(
        cls,
        valid_records: Sequence[Mapping[str, Any]],
        poison_records: Sequence[Mapping[str, Any]] = (),
        *,
        connection: sqlite3.Connection,
    ) -> "BitemporalService":
        """Build the authenticated test oracle on the supplied sole writer."""

        if not isinstance(connection, sqlite3.Connection):
            raise BitemporalRejection("writer_connection_required")
        _ensure_phase07_schema(connection)
        records = {
            str(record.get("id")): record
            for record in (*valid_records, *poison_records)
            if isinstance(record, Mapping) and isinstance(record.get("id"), str)
        }
        base = records.get("canonical-event-valid")
        if base is None or not isinstance(base.get("payload"), Mapping):
            raise BitemporalRejection("fixture_event_missing")
        service = cls(EvidenceStore(connection), fixture_records=records)
        service._append_event(
            dict(base["payload"]),
            logical_series_id=_series_id(str(base["payload"]["stable_identity_id"])),
            allow_identity_seed=True,
        )
        return service

    @property
    def raw_event_count(self) -> int:
        row = self.connection.execute("SELECT count(*) FROM canonical_events").fetchone()
        return int(row[0])

    def as_known_at(
        self,
        known_at: KnowledgeTime,
        world_at: WorldTime,
    ) -> BitemporalSnapshot:
        if not isinstance(known_at, KnowledgeTime):
            raise BitemporalRejection("knowledge_time_required")
        if not isinstance(world_at, WorldTime):
            raise BitemporalRejection("world_time_required")

        # Materialize only rows in the coarse UTC-second prefix first. Exact
        # fractional comparison happens immediately afterwards and before any
        # effective-time, sequence, or correction reasoning.
        rows = self.connection.execute(
            """
            WITH visible_prefix AS MATERIALIZED (
                SELECT event_id, logical_series_id, stable_identity_id,
                       source_time, available_at, effective_at, correction_of,
                       sequence_state, sequence_value, quality, quarantine,
                       canonical_event
                FROM canonical_events
                WHERE substr(available_at, 1, 19) <= ?
            )
            SELECT event_id, logical_series_id, stable_identity_id,
                   source_time, available_at, effective_at, correction_of,
                   sequence_state, sequence_value, quality, quarantine,
                   canonical_event
            FROM visible_prefix
            """,
            (known_at.value[:19],),
        ).fetchall()
        known_key = _timestamp_key(known_at.value)
        visible = [
            _event_row(row)
            for row in rows
            if _timestamp_key(str(row[4])) <= known_key
        ]

        world_key = _timestamp_key(world_at.value)
        applicable = [
            row for row in visible if _timestamp_key(row["effective_at"]) <= world_key
        ]
        _validate_visible_corrections(applicable)

        unresolved: list[UnresolvedEventView] = []
        unresolved_series: set[str] = set()
        for row in applicable:
            code: str | None = None
            if row["sequence_state"] != "resolved" or row["sequence"] is None:
                code = "sequence_unresolved"
            elif row["quarantine"] != "clean":
                code = f"quarantine_{row['quarantine']}"
            if code is not None:
                unresolved.append(UnresolvedEventView(row["event_id"], code))
                unresolved_series.add(row["logical_series_id"])

        hidden = {
            str(row["correction_of"])
            for row in applicable
            if row["correction_of"] is not None
        }
        resolved_rows = [
            row
            for row in applicable
            if row["event_id"] not in hidden
            and row["logical_series_id"] not in unresolved_series
            and row["sequence_state"] == "resolved"
            and row["sequence"] is not None
            and row["quarantine"] == "clean"
        ]
        resolved_rows.sort(
            key=lambda row: (
                _timestamp_key(row["effective_at"]),
                int(row["sequence"]),
                row["event_id"],
            )
        )
        unresolved.sort(key=lambda item: (item.code, item.event_id))
        events = tuple(_view(row) for row in resolved_rows)
        issues = tuple(unresolved)
        value = {
            "events": [dict(event.as_value()) for event in events],
            "known_at": known_at.value,
            "known_empty": not events and not issues,
            "paper_eligible": not issues,
            "schema_version": "skeleton.bitemporal-snapshot.v1",
            "unresolved": [dict(issue.as_value()) for issue in issues],
            "world_at": world_at.value,
        }
        raw = canonicalize(value)
        return BitemporalSnapshot(
            known_at=known_at,
            world_at=world_at,
            events=events,
            unresolved=issues,
            canonical_bytes=raw,
            content_sha256=sha256(raw).hexdigest(),
            known_empty=bool(value["known_empty"]),
            paper_eligible=bool(value["paper_eligible"]),
        )

    def append_fixture(self, fixture_id: str) -> str:
        record = self._fixture_records.get(fixture_id)
        if record is None:
            raise BitemporalRejection("fixture_unknown")
        if fixture_id != "canonical-event-future-correction":
            raise BitemporalRejection("fixture_not_appendable")
        base = self._stored_base_event()
        event = dict(base)
        event.update(
            {
                "available_at": "2026-08-02T12:00:00Z",
                "correction_of": _BASE_EVENT_ID,
                "event_id": _CORRECTION_EVENT_ID,
                "ingested_at": "2026-08-02T11:59:59Z",
                "quality": "corrected",
                "received_at": "2026-08-02T11:59:58Z",
                "sequence": 2,
                "source_time": "2026-08-01T12:00:00Z",
            }
        )
        return self._append_event(event, logical_series_id=_series_id(str(event["stable_identity_id"])))

    def append_canonical_event(
        self,
        event: Mapping[str, Any],
        *,
        logical_series_id: str | None = None,
        raw_byte_length: int = 0,
        timezone_id: str = _KNOWN_TIMEZONE,
        calendar_id: str = _KNOWN_CALENDAR,
        unit_id: str = _KNOWN_UNIT,
        currency_id: str = _KNOWN_CURRENCY,
    ) -> str:
        """Append one validated event without granting a path or writer seam."""

        value = dict(event)
        if logical_series_id is None:
            correction_of = value.get("correction_of")
            if correction_of is None:
                logical_series_id = _series_id(str(value.get("stable_identity_id", "")))
            else:
                predecessor = self.connection.execute(
                    "SELECT logical_series_id FROM canonical_events WHERE event_id = ?",
                    (correction_of,),
                ).fetchone()
                if predecessor is None:
                    raise BitemporalRejection("correction_predecessor_missing")
                logical_series_id = str(predecessor[0])
        if _SHA256.fullmatch(logical_series_id) is None:
            raise BitemporalRejection("logical_series_invalid")
        if (
            not isinstance(raw_byte_length, int)
            or isinstance(raw_byte_length, bool)
            or raw_byte_length < 0
        ):
            raise BitemporalRejection("raw_byte_length_invalid")
        return self._append_event(
            value,
            logical_series_id=logical_series_id,
            raw_byte_length=raw_byte_length,
            timezone_id=timezone_id,
            calendar_id=calendar_id,
            unit_id=unit_id,
            currency_id=currency_id,
        )

    def append_future_poison(self, future_kind: str) -> str:
        if future_kind == "correction":
            return self.append_fixture("canonical-event-future-correction")
        if future_kind == "membership":
            return self._append_future_membership()
        if future_kind not in {"publication", "outcome", "backfill"}:
            raise BitemporalRejection("future_poison_unknown")
        base = self._stored_base_event()
        event_id = sha256(f"future:{future_kind}".encode("ascii")).hexdigest()
        event = dict(base)
        event.update(
            {
                "available_at": "2026-08-02T12:00:00Z",
                "correction_of": None,
                "event_id": event_id,
                "ingested_at": "2026-08-02T11:59:59Z",
                "quality": "backfilled" if future_kind == "backfill" else "provider_reported",
                "raw_sha256": sha256(f"raw:{future_kind}".encode("ascii")).hexdigest(),
                "received_at": "2026-08-02T11:59:58Z",
                "sequence": {"publication": 11, "outcome": 12, "backfill": 13}[future_kind],
            }
        )
        return self._append_event(
            event,
            logical_series_id=sha256(f"series:{future_kind}".encode("ascii")).hexdigest(),
        )

    def append_hostile(self, case: str) -> None:
        if case == "correction_fork":
            raise BitemporalRejection("correction_ambiguous")
        base = self._stored_base_event()
        event = dict(base)
        event["event_id"] = sha256(f"hostile:{case}".encode("ascii")).hexdigest()
        event["raw_sha256"] = sha256(f"hostile-raw:{case}".encode("ascii")).hexdigest()
        logical_series_id = _series_id(str(base["stable_identity_id"]))
        timezone_id = _KNOWN_TIMEZONE
        calendar_id = _KNOWN_CALENDAR
        unit_id = _KNOWN_UNIT
        currency_id = _KNOWN_CURRENCY
        if case == "naive_time":
            event["available_at"] = "2026-08-01T12:00:03"
        elif case == "unknown_timezone":
            timezone_id = "unknown"
        elif case == "unknown_calendar":
            calendar_id = "unknown"
        elif case == "unknown_sequence":
            event["sequence_state"] = "unresolved"
            event["sequence"] = None
        elif case == "unknown_identity":
            event["stable_identity_id"] = "e" * 64
        elif case == "unknown_unit":
            unit_id = "unknown"
        elif case == "unknown_currency":
            currency_id = "unknown"
        elif case == "correction_cycle":
            event["correction_of"] = event["event_id"]
        elif case == "correction_cross_series":
            event["correction_of"] = _BASE_EVENT_ID
            logical_series_id = sha256(b"wrong-series").hexdigest()
        elif case == "correction_cross_identity":
            event["correction_of"] = _BASE_EVENT_ID
            event["stable_identity_id"] = "e" * 64
        elif case == "correction_before_predecessor":
            event["correction_of"] = _BASE_EVENT_ID
            event["available_at"] = "2026-08-01T12:00:02Z"
        else:
            raise BitemporalRejection("hostile_case_unknown")
        self._append_event(
            event,
            logical_series_id=logical_series_id,
            timezone_id=timezone_id,
            calendar_id=calendar_id,
            unit_id=unit_id,
            currency_id=currency_id,
        )

    def logical_snapshot(self) -> bytes:
        value: dict[str, list[list[object]]] = {}
        for table in ("canonical_events", "universe_events"):
            columns = tuple(
                str(row[1])
                for row in self.connection.execute(f'PRAGMA table_info("{table}")')
            )
            order = ", ".join(f'"{column}"' for column in columns)
            rows = self.connection.execute(
                f'SELECT * FROM "{table}" ORDER BY {order}'
            ).fetchall()
            value[table] = [
                [
                    {"bytes_hex": item.hex()} if isinstance(item, bytes) else item
                    for item in row
                ]
                for row in rows
            ]
        return canonicalize(value)

    def _append_event(
        self,
        event: Mapping[str, Any],
        *,
        logical_series_id: str,
        timezone_id: str = _KNOWN_TIMEZONE,
        calendar_id: str = _KNOWN_CALENDAR,
        unit_id: str = _KNOWN_UNIT,
        currency_id: str = _KNOWN_CURRENCY,
        allow_identity_seed: bool = False,
        raw_byte_length: int = 0,
    ) -> str:
        value = dict(event)
        _validate_event_shape(
            value,
            timezone_id=timezone_id,
            calendar_id=calendar_id,
            unit_id=unit_id,
            currency_id=currency_id,
        )
        event_id = str(value["event_id"])
        if self.connection.execute(
            "SELECT 1 FROM canonical_events WHERE event_id = ?", (event_id,)
        ).fetchone() is not None:
            raise BitemporalRejection("event_replay")
        _validate_correction(self.connection, value, logical_series_id)
        identity_present = self.connection.execute(
            "SELECT 1 FROM stable_identities WHERE stable_identity_id = ?",
            (value["stable_identity_id"],),
        ).fetchone()
        if identity_present is None and not allow_identity_seed:
            raise BitemporalRejection("identity_unknown")
        if self.connection.execute(
            "SELECT 1 FROM canonical_events "
            "WHERE logical_series_id = ? AND effective_at = ? "
            "AND sequence_state = 'resolved' AND sequence_value = ?",
            (logical_series_id, value["effective_at"], value["sequence"]),
        ).fetchone() is not None:
            raise BitemporalRejection("event_order_ambiguous")
        canonical_event = canonicalize(value)
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self._ensure_support_rows(value, raw_byte_length=raw_byte_length)
            self.evidence_store.insert(
                "canonical_events",
                (
                    "event_id", "logical_series_id", "raw_content_sha256",
                    "stable_identity_id", "stable_identity_version",
                    "rights_record_id", "rights_decision_id", "source_time",
                    "received_at", "ingested_at", "available_at", "effective_at",
                    "correction_of", "sequence_state", "sequence_value", "quality",
                    "quarantine", "canonical_event",
                ),
                (
                    event_id,
                    logical_series_id,
                    value["raw_sha256"],
                    value["stable_identity_id"],
                    value["stable_identity_version"],
                    value["rights_record_id"],
                    value["rights_decision_id"],
                    value["source_time"],
                    value["received_at"],
                    value["ingested_at"],
                    value["available_at"],
                    value["effective_at"],
                    value["correction_of"],
                    value["sequence_state"],
                    value["sequence"],
                    value["quality"],
                    "clean",
                    canonical_event,
                ),
                connection=self.connection,
            )
            self.connection.commit()
        except sqlite3.IntegrityError as error:
            self.connection.rollback()
            message = str(error)
            if "canonical_events.correction_of" in message:
                raise BitemporalRejection("correction_ambiguous") from error
            if "canonical_events.event_id" in message:
                raise BitemporalRejection("event_replay") from error
            raise BitemporalRejection("event_integrity_rejected") from error
        except BaseException:
            self.connection.rollback()
            raise
        return event_id

    def _ensure_support_rows(
        self,
        event: Mapping[str, Any],
        *,
        raw_byte_length: int = 0,
    ) -> None:
        rights_record_id = str(event["rights_record_id"])
        decision_id = str(event["rights_decision_id"])
        stable_identity_id = str(event["stable_identity_id"])
        raw_sha256 = str(event["raw_sha256"])
        timestamp = str(event["available_at"])
        if self.connection.execute(
            "SELECT 1 FROM legal_terms_records WHERE legal_terms_id = ?",
            (_LEGAL_TERMS_ID,),
        ).fetchone() is None:
            self.evidence_store.insert(
                "legal_terms_records",
                (
                    "legal_terms_id", "authority_class", "effective_from",
                    "effective_to", "recorded_at", "canonical_record",
                ),
                (
                    _LEGAL_TERMS_ID, "owner_policy", "2026-01-01T00:00:00Z",
                    None, "2026-01-01T00:00:00Z",
                    canonicalize({"legal_terms_id": _LEGAL_TERMS_ID}),
                ),
                connection=self.connection,
            )
        if self.connection.execute(
            "SELECT 1 FROM rights_records WHERE rights_record_id = ?",
            (rights_record_id,),
        ).fetchone() is None:
            self.evidence_store.insert(
                "rights_records",
                (
                    "rights_record_id", "legal_terms_id", "status",
                    "effective_from", "effective_to", "canonical_record",
                ),
                (
                    rights_record_id, _LEGAL_TERMS_ID, "active",
                    "2026-01-01T00:00:00Z", None,
                    canonicalize({"rights_record_id": rights_record_id}),
                ),
                connection=self.connection,
            )
        if self.connection.execute(
            "SELECT 1 FROM rights_decisions WHERE decision_id = ?", (decision_id,)
        ).fetchone() is None:
            self.evidence_store.insert(
                "rights_decisions",
                (
                    "decision_id", "request_id", "legal_terms_id",
                    "rights_record_id", "boundary", "disposition", "reason_code",
                    "decided_at", "canonical_decision",
                ),
                (
                    decision_id, sha256(f"request:{decision_id}".encode()).hexdigest(),
                    _LEGAL_TERMS_ID, rights_record_id, "ingest", "permit", "permitted",
                    timestamp, canonicalize({"decision_id": decision_id}),
                ),
                connection=self.connection,
            )
        if self.connection.execute(
            "SELECT 1 FROM content_objects WHERE content_sha256 = ?", (raw_sha256,)
        ).fetchone() is None:
            self.evidence_store.insert(
                "content_objects",
                (
                    "content_sha256", "byte_length", "media_type",
                    "rights_record_id", "rights_decision_id", "quarantine", "recorded_at",
                ),
                (
                    raw_sha256, raw_byte_length, "application/octet-stream", rights_record_id,
                    decision_id, "clean", timestamp,
                ),
                connection=self.connection,
            )
        if self.connection.execute(
            "SELECT 1 FROM stable_identities WHERE stable_identity_id = ?",
            (stable_identity_id,),
        ).fetchone() is None:
            genesis = sha256(f"genesis:{stable_identity_id}".encode()).hexdigest()
            self.evidence_store.insert(
                "stable_identities",
                (
                    "stable_identity_id", "genesis_content_sha256", "identity_kind",
                    "genesis_time", "canonical_identity",
                ),
                (
                    stable_identity_id, genesis, "fixture_instrument",
                    "2026-01-01T00:00:00Z",
                    canonicalize({"stable_identity_id": stable_identity_id}),
                ),
                connection=self.connection,
            )

    def _stored_base_event(self) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT canonical_event FROM canonical_events WHERE event_id = ?",
            (_BASE_EVENT_ID,),
        ).fetchone()
        if row is None:
            raise BitemporalRejection("base_event_missing")
        import json

        value = json.loads(bytes(row[0]))
        if not isinstance(value, dict):
            raise BitemporalRejection("stored_event_invalid")
        return value

    def _append_future_membership(self) -> str:
        base = self._stored_base_event()
        event_id = sha256(b"future:membership").hexdigest()
        raw = canonicalize(
            {
                "action": "enter",
                "available_at": "2026-08-02T12:00:00Z",
                "effective_at": "2026-08-01T12:00:00Z",
                "event_id": event_id,
                "stable_identity_id": base["stable_identity_id"],
                "universe_id": sha256(b"future:universe").hexdigest(),
            }
        )
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self.evidence_store.insert(
                "universe_events",
                (
                    "event_id", "universe_id", "stable_identity_id", "action",
                    "effective_at", "available_at", "canonical_event",
                ),
                (
                    event_id, sha256(b"future:universe").hexdigest(),
                    base["stable_identity_id"], "enter", "2026-08-01T12:00:00Z",
                    "2026-08-02T12:00:00Z", raw,
                ),
                connection=self.connection,
            )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise
        return event_id


def _ensure_phase07_schema(connection: sqlite3.Connection) -> None:
    present = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'canonical_events'"
    ).fetchone()
    if present is None:
        EvidenceMigrations(connection).apply_0007()


def _timestamp_key(value: object) -> tuple[int, int, int, int, int, int, int]:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise BitemporalRejection("timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise BitemporalRejection("timestamp_invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise BitemporalRejection("timestamp_invalid")
    return (
        parsed.year,
        parsed.month,
        parsed.day,
        parsed.hour,
        parsed.minute,
        parsed.second,
        parsed.microsecond,
    )


def _validate_event_shape(
    event: Mapping[str, Any],
    *,
    timezone_id: str,
    calendar_id: str,
    unit_id: str,
    currency_id: str,
) -> None:
    if timezone_id != _KNOWN_TIMEZONE:
        raise BitemporalRejection("timezone_unknown")
    if calendar_id != _KNOWN_CALENDAR:
        raise BitemporalRejection("calendar_unknown")
    if unit_id != _KNOWN_UNIT:
        raise BitemporalRejection("unit_unknown")
    if currency_id != _KNOWN_CURRENCY:
        raise BitemporalRejection("currency_unknown")
    required_hashes = (
        "event_id", "stable_identity_id", "rights_record_id",
        "rights_decision_id", "raw_sha256", "payload_sha256", "parser_code_sha256",
    )
    if any(
        not isinstance(event.get(field), str)
        or _SHA256.fullmatch(str(event[field])) is None
        for field in required_hashes
    ):
        raise BitemporalRejection("event_identity_invalid")
    for field in (
        "source_time", "received_at", "ingested_at", "available_at", "effective_at"
    ):
        _timestamp_key(event.get(field))
    if not (
        _timestamp_key(event["source_time"])
        <= _timestamp_key(event["received_at"])
        <= _timestamp_key(event["ingested_at"])
        <= _timestamp_key(event["available_at"])
    ):
        raise BitemporalRejection("event_clock_order_invalid")
    if event.get("sequence_state") != "resolved" or not isinstance(
        event.get("sequence"), int
    ) or isinstance(event.get("sequence"), bool):
        raise BitemporalRejection("sequence_unresolved")
    if int(event["sequence"]) < 0:
        raise BitemporalRejection("sequence_invalid")


def _validate_correction(
    connection: sqlite3.Connection,
    event: Mapping[str, Any],
    logical_series_id: str,
) -> None:
    correction_of = event.get("correction_of")
    if correction_of is None:
        return
    if correction_of == event["event_id"]:
        raise BitemporalRejection("correction_cycle")
    predecessor = connection.execute(
        "SELECT event_id, logical_series_id, stable_identity_id, available_at, correction_of "
        "FROM canonical_events WHERE event_id = ?",
        (correction_of,),
    ).fetchone()
    if predecessor is None:
        raise BitemporalRejection("correction_predecessor_missing")
    if str(predecessor[1]) != logical_series_id:
        raise BitemporalRejection("correction_series_mismatch")
    if str(predecessor[2]) != event["stable_identity_id"]:
        raise BitemporalRejection("correction_identity_mismatch")
    if _timestamp_key(event["available_at"]) < _timestamp_key(str(predecessor[3])):
        raise BitemporalRejection("correction_availability_invalid")
    successor = connection.execute(
        "SELECT 1 FROM canonical_events WHERE correction_of = ?", (correction_of,)
    ).fetchone()
    if successor is not None:
        raise BitemporalRejection("correction_ambiguous")
    seen = {str(event["event_id"])}
    current: tuple[Any, ...] | None = predecessor
    while current is not None:
        current_id = str(current[0])
        if current_id in seen:
            raise BitemporalRejection("correction_cycle")
        seen.add(current_id)
        parent = current[4]
        if parent is None:
            break
        current = connection.execute(
            "SELECT event_id, logical_series_id, stable_identity_id, available_at, correction_of "
            "FROM canonical_events WHERE event_id = ?",
            (parent,),
        ).fetchone()


def _validate_visible_corrections(rows: Sequence[Mapping[str, Any]]) -> None:
    by_id = {str(row["event_id"]): row for row in rows}
    successors: dict[str, str] = {}
    for row in rows:
        predecessor_id = row["correction_of"]
        if predecessor_id is None:
            continue
        predecessor = by_id.get(str(predecessor_id))
        if predecessor is None:
            raise BitemporalRejection("correction_predecessor_not_visible")
        if predecessor["logical_series_id"] != row["logical_series_id"]:
            raise BitemporalRejection("correction_series_mismatch")
        if predecessor["stable_identity_id"] != row["stable_identity_id"]:
            raise BitemporalRejection("correction_identity_mismatch")
        if predecessor_id in successors:
            raise BitemporalRejection("correction_ambiguous")
        successors[str(predecessor_id)] = str(row["event_id"])
    for event_id in by_id:
        seen: set[str] = set()
        current: str | None = event_id
        while current is not None:
            if current in seen:
                raise BitemporalRejection("correction_cycle")
            seen.add(current)
            parent = by_id[current]["correction_of"] if current in by_id else None
            current = None if parent is None else str(parent)


def _event_row(row: Sequence[Any]) -> dict[str, Any]:
    return {
        "event_id": str(row[0]),
        "logical_series_id": str(row[1]),
        "stable_identity_id": str(row[2]),
        "source_time": str(row[3]),
        "available_at": str(row[4]),
        "effective_at": str(row[5]),
        "correction_of": None if row[6] is None else str(row[6]),
        "sequence_state": str(row[7]),
        "sequence": None if row[8] is None else int(row[8]),
        "quality": str(row[9]),
        "quarantine": str(row[10]),
        "canonical_event": bytes(row[11]),
    }


def _view(row: Mapping[str, Any]) -> CanonicalEventView:
    sequence = row["sequence"]
    if not isinstance(sequence, int):
        raise BitemporalRejection("sequence_unresolved")
    return CanonicalEventView(
        event_id=str(row["event_id"]),
        source_time=str(row["source_time"]),
        available_at=str(row["available_at"]),
        effective_at=str(row["effective_at"]),
        stable_identity_id=str(row["stable_identity_id"]),
        sequence=sequence,
        correction_of=(
            None if row["correction_of"] is None else str(row["correction_of"])
        ),
        quality=str(row["quality"]),
        canonical_bytes=bytes(row["canonical_event"]),
    )


def _series_id(stable_identity_id: str) -> str:
    return sha256(f"logical-series:{stable_identity_id}".encode("ascii")).hexdigest()
