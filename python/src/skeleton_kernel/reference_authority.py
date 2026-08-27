"""Durable generic single-writer authority with three fenced transactions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import secrets
import sqlite3
import struct
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .authorization import AuthorizationRejection, _authorization_body, _timestamp
from .canonical import canonicalize, parse_raw_json, sha256_hex
from .constitution import (
    ConstitutionRejection,
    verify_current_signer,
    verify_historical_signer,
)
from .lifecycle import LifecycleEvent, LifecycleRejection
from .authority_protocol import (
    AUTHORITY_RESULT_CLASS,
    AUTHORITY_RESULT_CLASS_TAG,
    AUTHORITY_RESULT_DOMAIN,
    AUTHORITY_RESULT_SCHEMA_ID,
    AuthorityCommand,
)
from .schema_registry import SchemaRegistry
from .store import KernelStore


ZERO_HASH = "0" * 64
MAGIC = b"SKELETON-SIGNATURE-PREIMAGE\x00"
CONFIG_SHA256 = "6c6459693c3ca97a0204995da6d1116f3ab2e62c962a99a549c345989704835e"
CONFIG_SCHEMA_VERSION = "skeleton.authority-domains.v1"
JOURNAL_STATES = frozenset(
    {"RECEIVED", "EFFECT_COMMITTED", "RESULT_COMMITTED"}
)
TIMESTAMP = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?Z$"
)
EFFECT_TARGETS = {
    "activate": "active",
    "deactivate": "removed",
    "pause": "suspended",
    "resume": "active",
    "revoke": "removed",
}


@dataclass(slots=True)
class AuthorityRejection(ValueError):
    """Stable rejection with no command, secret, or stored-byte echo."""

    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class AuthorityDomain:
    authority_domain: str
    subject_type: str
    subject_id: str
    allowed_effects: frozenset[str]


@dataclass(frozen=True, slots=True)
class AuthorityHashes:
    semantic_state_sha256: str
    journal_state_sha256: str
    authority_snapshot_sha256: str


@dataclass(frozen=True, slots=True)
class AuthorityEvidence:
    authority_domain: str
    journal_state: str | None
    receipt_count: int
    effect_count: int
    result_count: int
    lifecycle_event_count: int
    semantic_state_sha256: str
    journal_state_sha256: str
    authority_snapshot_sha256: str
    receipt_fence_token: int | None
    effect_fence_token: int | None
    result_fence_token: int | None
    result_bytes: bytes | None


class ReferenceAuthority:
    """Sole mutation path for one configured authoritative SQLite domain."""

    __slots__ = (
        "_domain",
        "_after_commit",
        "_fence_token",
        "_lease_now",
        "_registry",
        "_signer",
        "_store",
        "_writer_id",
    )

    def __init__(
        self,
        *,
        database_path: Path,
        authority_domains_path: Path,
        registry: SchemaRegistry,
        result_signing_seed_path: Path,
        lease_now: str,
        lease_seconds: int,
        after_commit: Callable[[str], None] | None = None,
    ) -> None:
        domains = load_authority_domains(authority_domains_path)
        if len(domains) != 1:
            raise AuthorityRejection("authority_domain_configuration_invalid")
        self._domain = domains[0]
        self._after_commit = after_commit or _no_after_commit
        self._registry = registry
        self._lease_now = _parse_time(lease_now, "authority_clock_invalid")
        if not isinstance(lease_seconds, int) or not 1 <= lease_seconds <= 300:
            raise AuthorityRejection("authority_lease_duration_invalid")
        path = database_path.resolve(strict=True)
        connection = sqlite3.connect(path, isolation_level=None, timeout=2.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 2000")
        self._store = KernelStore(connection, path)
        self._writer_id = secrets.token_hex(32)
        try:
            _ensure_authority_schema(connection)
            self._signer = load_result_signer(
                result_signing_seed_path,
                self._store,
            )
            self._fence_token = self._acquire_lease(lease_seconds)
        except BaseException:
            connection.close()
            raise

    @property
    def authority_domain(self) -> str:
        return self._domain.authority_domain

    @property
    def fence_token(self) -> int:
        return self._fence_token

    def close(self) -> None:
        self._store.close()

    def hashes(self) -> AuthorityHashes:
        return _hashes(self._store.connection, self._domain)

    def execute(self, command: AuthorityCommand) -> bytes:
        if command.authority_domain != self._domain.authority_domain:
            raise AuthorityRejection("authority_domain_unauthorized")
        if command.lifecycle_effect not in self._domain.allowed_effects:
            raise AuthorityRejection("authority_effect_unauthorized")
        existing = self._store.connection.execute(
            "SELECT * FROM authority_command_journal "
            "WHERE authority_domain = ? AND command_id = ?",
            (command.authority_domain, command.command_id),
        ).fetchone()
        if existing is None:
            self._accept(command)
            self._after_commit("after_accept_commit")
            existing_state = "RECEIVED"
        else:
            if existing["payload_sha256"] != command.payload_sha256:
                raise AuthorityRejection("command_payload_mismatch")
            existing_state = str(existing["journal_state"])
            if existing_state == "RESULT_COMMITTED":
                return self._stored_result(command)
        if existing_state == "RECEIVED":
            self._apply(command)
            self._after_commit("after_apply_commit")
            existing_state = "EFFECT_COMMITTED"
        if existing_state == "EFFECT_COMMITTED":
            self._finalize(command)
            self._after_commit("after_finalize_commit_before_send")
        return self._stored_result(command)

    def _acquire_lease(self, lease_seconds: int) -> int:
        expires = self._lease_now + timedelta(seconds=lease_seconds)
        acquired_at = _format_time(self._lease_now)
        expires_at = _format_time(expires)
        with self._store.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM writer_leases WHERE authority_domain = ?",
                (self.authority_domain,),
            ).fetchone()
            if row is None:
                token = 1
                cursor = connection.execute(
                    """
                    INSERT INTO writer_leases(
                        authority_domain, writer_id, fence_epoch,
                        lease_acquired_at, lease_expires_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        self.authority_domain,
                        self._writer_id,
                        token,
                        acquired_at,
                        expires_at,
                    ),
                )
            else:
                current_expiry = _parse_time(
                    str(row["lease_expires_at"]),
                    "authority_lease_corrupt",
                )
                if current_expiry > self._lease_now:
                    raise AuthorityRejection("writer_lease_held")
                token = int(row["fence_epoch"]) + 1
                cursor = connection.execute(
                    """
                    UPDATE writer_leases
                    SET writer_id = ?, fence_epoch = ?,
                        lease_acquired_at = ?, lease_expires_at = ?
                    WHERE authority_domain = ? AND fence_epoch = ?
                    """,
                    (
                        self._writer_id,
                        token,
                        acquired_at,
                        expires_at,
                        self.authority_domain,
                        int(row["fence_epoch"]),
                    ),
                )
                if cursor.rowcount != 1:
                    raise AuthorityRejection("writer_lease_conflict")
        return token

    def _require_fence(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT writer_id, fence_epoch, lease_expires_at "
            "FROM writer_leases WHERE authority_domain = ?",
            (self.authority_domain,),
        ).fetchone()
        if (
            row is None
            or row["writer_id"] != self._writer_id
            or int(row["fence_epoch"]) != self._fence_token
            or _parse_time(
                str(row["lease_expires_at"]),
                "authority_lease_corrupt",
            )
            <= self._lease_now
        ):
            raise AuthorityRejection("stale_fence")

    def _accept(self, command: AuthorityCommand) -> None:
        with self._store.transaction() as connection:
            self._require_fence(connection)
            if connection.execute(
                "SELECT 1 FROM authority_command_journal "
                "WHERE authority_domain = ? AND command_id = ?",
                (self.authority_domain, command.command_id),
            ).fetchone():
                raise AuthorityRejection("command_receipt_conflict")
            current = _semantic_state_hash(connection, self._domain)
            if command.expected_state_sha256 != current:
                raise AuthorityRejection("stale_expected_state")
            self._validate_authorization(connection, command, consume=False)
            connection.execute(
                """
                INSERT INTO command_receipts(
                    authority_domain, command_id, request_sha256, received_at,
                    semantic_pre_sha256, accepted_fence_epoch
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    self.authority_domain,
                    command.command_id,
                    command.payload_sha256,
                    command.requested_at,
                    current,
                    self._fence_token,
                ),
            )
            connection.execute(
                """
                INSERT INTO authority_command_journal(
                    authority_domain, command_id, payload_sha256,
                    journal_state, semantic_pre_sha256,
                    semantic_post_sha256, result_sha256, last_fence_epoch,
                    received_journal_sha256, received_snapshot_sha256,
                    effect_journal_sha256, effect_snapshot_sha256,
                    result_journal_sha256, result_snapshot_sha256
                ) VALUES (?, ?, ?, 'RECEIVED', ?, NULL, NULL, ?, NULL, NULL,
                          NULL, NULL, NULL, NULL)
                """,
                (
                    self.authority_domain,
                    command.command_id,
                    command.payload_sha256,
                    current,
                    self._fence_token,
                ),
            )
            hashes = _hashes(connection, self._domain)
            connection.execute(
                """
                UPDATE authority_command_journal
                SET received_journal_sha256 = ?,
                    received_snapshot_sha256 = ?
                WHERE authority_domain = ? AND command_id = ?
                  AND journal_state = 'RECEIVED'
                """,
                (
                    hashes.journal_state_sha256,
                    hashes.authority_snapshot_sha256,
                    self.authority_domain,
                    command.command_id,
                ),
            )

    def _apply(self, command: AuthorityCommand) -> None:
        with self._store.transaction() as connection:
            self._require_fence(connection)
            journal = self._journal_for_update(connection, command)
            if journal["journal_state"] != "RECEIVED":
                raise AuthorityRejection("illegal_journal_transition")
            semantic_pre = _semantic_state_hash(connection, self._domain)
            if semantic_pre != journal["semantic_pre_sha256"]:
                raise AuthorityRejection("semantic_pre_state_mismatch")
            authorization_sha256 = self._validate_authorization(
                connection,
                command,
                consume=True,
            )
            event = self._build_lifecycle_event(
                connection,
                command,
                authorization_sha256,
            )
            _insert_lifecycle_event(connection, event)
            semantic_post = _semantic_state_hash(connection, self._domain)
            connection.execute(
                """
                INSERT INTO command_effects(
                    authority_domain, command_id, effect_sha256,
                    pre_state_sha256, post_state_sha256,
                    fence_epoch, committed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.authority_domain,
                    command.command_id,
                    event.event_sha256,
                    semantic_pre,
                    semantic_post,
                    self._fence_token,
                    command.requested_at,
                ),
            )
            connection.execute(
                """
                UPDATE authority_command_journal
                SET journal_state = 'EFFECT_COMMITTED',
                    semantic_post_sha256 = ?,
                    last_fence_epoch = ?
                WHERE authority_domain = ? AND command_id = ?
                  AND journal_state = 'RECEIVED'
                  AND payload_sha256 = ?
                """,
                (
                    semantic_post,
                    self._fence_token,
                    self.authority_domain,
                    command.command_id,
                    command.payload_sha256,
                ),
            )
            hashes = _hashes(connection, self._domain)
            connection.execute(
                """
                UPDATE authority_command_journal
                SET effect_journal_sha256 = ?, effect_snapshot_sha256 = ?
                WHERE authority_domain = ? AND command_id = ?
                  AND journal_state = 'EFFECT_COMMITTED'
                """,
                (
                    hashes.journal_state_sha256,
                    hashes.authority_snapshot_sha256,
                    self.authority_domain,
                    command.command_id,
                ),
            )

    def _finalize(self, command: AuthorityCommand) -> None:
        with self._store.transaction() as connection:
            self._require_fence(connection)
            journal = self._journal_for_update(connection, command)
            if journal["journal_state"] != "EFFECT_COMMITTED":
                raise AuthorityRejection("illegal_journal_transition")
            semantic_post = _semantic_state_hash(connection, self._domain)
            if semantic_post != journal["semantic_post_sha256"]:
                raise AuthorityRejection("semantic_post_state_mismatch")
            result_bytes = self._build_result(connection, command, journal)
            result_sha256 = sha256_hex(result_bytes)
            connection.execute(
                """
                INSERT INTO command_results(
                    authority_domain, command_id, result_sha256,
                    fence_epoch, committed_at, result_bytes
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    self.authority_domain,
                    command.command_id,
                    result_sha256,
                    self._fence_token,
                    command.requested_at,
                    result_bytes,
                ),
            )
            connection.execute(
                """
                UPDATE authority_command_journal
                SET journal_state = 'RESULT_COMMITTED',
                    result_sha256 = ?, last_fence_epoch = ?
                WHERE authority_domain = ? AND command_id = ?
                  AND journal_state = 'EFFECT_COMMITTED'
                  AND payload_sha256 = ?
                """,
                (
                    result_sha256,
                    self._fence_token,
                    self.authority_domain,
                    command.command_id,
                    command.payload_sha256,
                ),
            )
            hashes = _hashes(connection, self._domain)
            connection.execute(
                """
                UPDATE authority_command_journal
                SET result_journal_sha256 = ?, result_snapshot_sha256 = ?
                WHERE authority_domain = ? AND command_id = ?
                  AND journal_state = 'RESULT_COMMITTED'
                """,
                (
                    hashes.journal_state_sha256,
                    hashes.authority_snapshot_sha256,
                    self.authority_domain,
                    command.command_id,
                ),
            )

    def _journal_for_update(
        self,
        connection: sqlite3.Connection,
        command: AuthorityCommand,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM authority_command_journal "
            "WHERE authority_domain = ? AND command_id = ?",
            (self.authority_domain, command.command_id),
        ).fetchone()
        if row is None:
            raise AuthorityRejection("command_receipt_missing")
        if row["payload_sha256"] != command.payload_sha256:
            raise AuthorityRejection("command_payload_mismatch")
        return row

    def _validate_authorization(
        self,
        connection: sqlite3.Connection,
        command: AuthorityCommand,
        *,
        consume: bool,
    ) -> str:
        row = connection.execute(
            "SELECT * FROM authorizations WHERE authorization_id = ?",
            (command.authorization_id,),
        ).fetchone()
        if row is None:
            raise AuthorityRejection("authorization_not_found")
        epoch_row = connection.execute(
            "SELECT signer_set_epoch FROM signer_set_epochs "
            "ORDER BY length(signer_set_epoch) DESC, signer_set_epoch DESC LIMIT 1"
        ).fetchone()
        if epoch_row is None or row["signer_set_epoch"] != epoch_row["signer_set_epoch"]:
            raise AuthorityRejection("authorization_signer_epoch_inactive")
        if connection.execute(
            "SELECT 1 FROM authorization_revocations WHERE authorization_id = ?",
            (command.authorization_id,),
        ).fetchone():
            raise AuthorityRejection("authorization_revoked")
        raw_grant = bytes(row["canonical_grant"])
        try:
            grant = parse_raw_json(raw_grant)
            if not isinstance(grant, dict) or canonicalize(grant) != raw_grant:
                raise AuthorityRejection("authorization_store_corrupt")
            if sha256_hex(raw_grant) != row["decision_sha256"]:
                raise AuthorityRejection("authorization_store_corrupt")
            verify_current_signer(
                grant,
                self._store,
                expected_object_class="authority_grant",
                expected_domain="skeleton.authority-grant.v1",
                class_tag=0x02,
            )
            body = _authorization_body(grant.get("body"))
        except AuthorityRejection:
            raise
        except (AuthorizationRejection, ConstitutionRejection, Exception) as error:
            code = getattr(error, "code", "authorization_store_corrupt")
            raise AuthorityRejection(str(code)) from error
        if body["authorization_id"] != command.authorization_id:
            raise AuthorityRejection("authorization_store_corrupt")
        if body["action"] != command.lifecycle_effect:
            raise AuthorityRejection("authorization_action_mismatch")
        if body["scope"] != self.authority_domain or body["subject"] != self.authority_domain:
            raise AuthorityRejection("authorization_scope_mismatch")
        if body["reauthentication_proof_sha256"] == ZERO_HASH:
            raise AuthorityRejection("reauthentication_required")
        command_time = _parse_time(command.requested_at, "authority_command_time_invalid")
        if command_time < _timestamp(
            body["issued_at"],
            "authorization_issued_at_malformed",
        ):
            raise AuthorityRejection("authorization_not_yet_valid")
        if command_time >= _timestamp(
            body["expires_at"],
            "authorization_expires_at_malformed",
        ):
            raise AuthorityRejection("authorization_expired")
        if row["used_at"] is not None and not bool(row["reusable"]):
            raise AuthorityRejection("authorization_already_used")
        decision = canonicalize(
            {
                "action": command.lifecycle_effect,
                "authorization_id": command.authorization_id,
                "command_id": command.command_id,
                "scope": self.authority_domain,
                "signer_set_epoch": str(row["signer_set_epoch"]),
                "used_at": command.requested_at,
            }
        )
        decision_sha256 = sha256_hex(decision)
        if consume:
            if not bool(row["reusable"]):
                cursor = connection.execute(
                    "UPDATE authorizations SET used_at = ? "
                    "WHERE authorization_id = ? AND used_at IS NULL",
                    (command.requested_at, command.authorization_id),
                )
                if cursor.rowcount != 1:
                    raise AuthorityRejection("authorization_already_used")
            try:
                connection.execute(
                    """
                    INSERT INTO authorization_decisions(
                        decision_sha256, authorization_id, decision_code,
                        canonical_input, decided_at
                    ) VALUES (?, ?, 'authorized', ?, ?)
                    """,
                    (
                        decision_sha256,
                        command.authorization_id,
                        decision,
                        command.requested_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise AuthorityRejection("authorization_decision_replay") from error
        return decision_sha256

    def _build_lifecycle_event(
        self,
        connection: sqlite3.Connection,
        command: AuthorityCommand,
        authorization_sha256: str,
    ) -> LifecycleEvent:
        subject = connection.execute(
            "SELECT lifecycle_state, state_sha256 FROM subjects "
            "WHERE subject_type = ? AND subject_id = ?",
            (self._domain.subject_type, self._domain.subject_id),
        ).fetchone()
        prior_state = "absent" if subject is None else str(subject["lifecycle_state"])
        prior_hash = ZERO_HASH if subject is None else str(subject["state_sha256"])
        value = {
            "schema_version": "skeleton.lifecycle-event.v1",
            "event_id": command.command_id,
            "subject": {
                "subject_type": self._domain.subject_type,
                "subject_id": self._domain.subject_id,
            },
            "prior_state": prior_state,
            "new_state": EFFECT_TARGETS[command.lifecycle_effect],
            "cause": {
                "code": "authority_command",
                "evidence_sha256": command.payload_sha256,
            },
            "authorization": {
                "mode": "material_authorization",
                "evidence_sha256": authorization_sha256,
            },
            "occurred_at": command.requested_at,
        }
        try:
            return LifecycleEvent.from_dict(value, prior_state_sha256=prior_hash)
        except LifecycleRejection as error:
            raise AuthorityRejection(error.code) from error

    def _build_result(
        self,
        connection: sqlite3.Connection,
        command: AuthorityCommand,
        journal: sqlite3.Row,
    ) -> bytes:
        epoch = self._store.current_signer_epoch()
        if self._signer.key_id not in self._store.active_signer_ids():
            raise AuthorityRejection("result_signer_inactive")
        body = {
            "schema_version": "skeleton.authority-result.body.v1",
            "authority_domain": self.authority_domain,
            "command_id": command.command_id,
            "disposition": "committed",
            "state_before_sha256": str(journal["semantic_pre_sha256"]),
            "state_after_sha256": str(journal["semantic_post_sha256"]),
            "event_id": command.command_id,
            "completed_at": command.requested_at,
        }
        envelope: dict[str, Any] = {
            "signature_protocol_version": 1,
            "object_class": AUTHORITY_RESULT_CLASS,
            "signature_domain": AUTHORITY_RESULT_DOMAIN,
            "signer_key_id": self._signer.key_id,
            "signer_set_epoch": epoch,
            "body": body,
            "signature": "",
        }
        envelope["signature"] = self._signer.private_key.sign(
            authority_result_preimage(envelope)
        ).hex()
        raw = canonicalize(envelope)
        try:
            validated = self._registry.validate_raw(raw, AUTHORITY_RESULT_SCHEMA_ID)
            if validated.canonical_bytes != raw:
                raise AuthorityRejection("authority_result_noncanonical")
            verify_current_signer(
                envelope,
                self._store,
                expected_object_class=AUTHORITY_RESULT_CLASS,
                expected_domain=AUTHORITY_RESULT_DOMAIN,
                class_tag=AUTHORITY_RESULT_CLASS_TAG,
            )
        except AuthorityRejection:
            raise
        except Exception as error:
            raise AuthorityRejection("authority_result_invalid") from error
        return raw

    def _stored_result(self, command: AuthorityCommand) -> bytes:
        row = self._store.connection.execute(
            """
            SELECT r.result_sha256, r.result_bytes, j.payload_sha256,
                   j.result_sha256 AS journal_result_sha256,
                   j.journal_state
            FROM authority_command_journal AS j
            JOIN command_results AS r USING(authority_domain, command_id)
            WHERE j.authority_domain = ? AND j.command_id = ?
            """,
            (self.authority_domain, command.command_id),
        ).fetchone()
        if (
            row is None
            or row["journal_state"] != "RESULT_COMMITTED"
            or row["payload_sha256"] != command.payload_sha256
            or row["result_bytes"] is None
        ):
            raise AuthorityRejection("terminal_result_corrupt")
        raw = bytes(row["result_bytes"])
        digest = sha256_hex(raw)
        if digest != row["result_sha256"] or digest != row["journal_result_sha256"]:
            raise AuthorityRejection("terminal_result_corrupt")
        try:
            validated = self._registry.validate_raw(raw, AUTHORITY_RESULT_SCHEMA_ID)
            if validated.canonical_bytes != raw:
                raise AuthorityRejection("terminal_result_corrupt")
            value = validated.value
            if not isinstance(value, dict):
                raise AuthorityRejection("terminal_result_corrupt")
            verify_historical_signer(
                value,
                self._store,
                expected_object_class=AUTHORITY_RESULT_CLASS,
                expected_domain=AUTHORITY_RESULT_DOMAIN,
                class_tag=AUTHORITY_RESULT_CLASS_TAG,
            )
        except AuthorityRejection:
            raise
        except Exception as error:
            raise AuthorityRejection("terminal_result_corrupt") from error
        return raw


@dataclass(frozen=True, slots=True)
class ResultSigner:
    private_key: Ed25519PrivateKey
    key_id: str


def load_authority_domains(path: Path) -> tuple[AuthorityDomain, ...]:
    raw = path.resolve(strict=True).read_bytes()
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise AuthorityRejection("authority_domain_configuration_invalid") from error
    if sha256_hex(canonicalize(value)) != CONFIG_SHA256:
        raise AuthorityRejection("authority_domain_config_digest_mismatch")
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "domains"}
        or value["schema_version"] != CONFIG_SCHEMA_VERSION
        or not isinstance(value["domains"], list)
        or not value["domains"]
    ):
        raise AuthorityRejection("authority_domain_configuration_invalid")
    domains: list[AuthorityDomain] = []
    seen: set[str] = set()
    for item in value["domains"]:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "authority_domain",
                "subject_type",
                "subject_id",
                "allowed_effects",
            }
            or not isinstance(item["authority_domain"], str)
            or not item["authority_domain"]
            or item["authority_domain"] in seen
            or not isinstance(item["subject_type"], str)
            or not item["subject_type"]
            or not _is_hash(item["subject_id"])
            or not isinstance(item["allowed_effects"], list)
            or item["allowed_effects"] != sorted(EFFECT_TARGETS)
            or len(item["allowed_effects"]) != len(set(item["allowed_effects"]))
        ):
            raise AuthorityRejection("authority_domain_configuration_invalid")
        seen.add(item["authority_domain"])
        domains.append(
            AuthorityDomain(
                authority_domain=item["authority_domain"],
                subject_type=item["subject_type"],
                subject_id=item["subject_id"],
                allowed_effects=frozenset(item["allowed_effects"]),
            )
        )
    return tuple(domains)


def inspect_authority_database(
    database_path: Path,
    authority_domain: str,
) -> AuthorityEvidence:
    domain = next(
        (
            item
            for item in _expected_domains()
            if item.authority_domain == authority_domain
        ),
        None,
    )
    if domain is None:
        raise AuthorityRejection("authority_domain_unauthorized")
    path = database_path.resolve(strict=True)
    connection = sqlite3.connect(
        f"{path.as_uri()}?mode=ro",
        uri=True,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    try:
        hashes = _hashes(connection, domain)
        journal = connection.execute(
            "SELECT * FROM authority_command_journal "
            "WHERE authority_domain = ? ORDER BY rowid",
            (authority_domain,),
        ).fetchall()
        current = journal[-1] if journal else None
        receipt = connection.execute(
            "SELECT accepted_fence_epoch FROM command_receipts "
            "WHERE authority_domain = ? ORDER BY command_id",
            (authority_domain,),
        ).fetchall()
        effect = connection.execute(
            "SELECT fence_epoch FROM command_effects "
            "WHERE authority_domain = ? ORDER BY command_id",
            (authority_domain,),
        ).fetchall()
        result = connection.execute(
            "SELECT fence_epoch, result_bytes FROM command_results "
            "WHERE authority_domain = ? ORDER BY command_id",
            (authority_domain,),
        ).fetchall()
        _verify_current_evidence(current, hashes)
        return AuthorityEvidence(
            authority_domain=authority_domain,
            journal_state=(
                None if current is None else str(current["journal_state"])
            ),
            receipt_count=len(receipt),
            effect_count=len(effect),
            result_count=len(result),
            lifecycle_event_count=int(
                connection.execute(
                    "SELECT count(*) FROM lifecycle_events "
                    "WHERE subject_type = ? AND subject_id = ?",
                    (domain.subject_type, domain.subject_id),
                ).fetchone()[0]
            ),
            semantic_state_sha256=hashes.semantic_state_sha256,
            journal_state_sha256=hashes.journal_state_sha256,
            authority_snapshot_sha256=hashes.authority_snapshot_sha256,
            receipt_fence_token=(
                None if not receipt else int(receipt[-1]["accepted_fence_epoch"])
            ),
            effect_fence_token=(
                None if not effect else int(effect[-1]["fence_epoch"])
            ),
            result_fence_token=(
                None if not result else int(result[-1]["fence_epoch"])
            ),
            result_bytes=(
                None
                if not result or result[-1]["result_bytes"] is None
                else bytes(result[-1]["result_bytes"])
            ),
        )
    finally:
        connection.close()


def _expected_domains() -> tuple[AuthorityDomain, ...]:
    return (
        AuthorityDomain(
            authority_domain="project-lifecycle",
            subject_type="project",
            subject_id=(
                "73c5fcf5c80bd7b5a9cd65d499d53bb4"
                "98131322d29d4229cdbd425580346329"
            ),
            allowed_effects=frozenset(EFFECT_TARGETS),
        ),
    )


def _ensure_authority_schema(connection: sqlite3.Connection) -> None:
    required = {
        "subjects",
        "lifecycle_events",
        "proposal_replay_ids",
        "authorizations",
        "authorization_revocations",
        "authorization_decisions",
        "writer_leases",
        "command_receipts",
        "command_effects",
        "command_results",
        "signer_set_epochs",
        "signer_set_members",
        "signer_revocations",
    }
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    if not required.issubset(present):
        raise AuthorityRejection("authority_store_schema_missing")
    additions = {
        "writer_leases": (
            (
                "lease_acquired_at",
                "TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'",
            ),
            (
                "lease_expires_at",
                "TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'",
            ),
        ),
        "command_receipts": (
            ("semantic_pre_sha256", f"TEXT NOT NULL DEFAULT '{ZERO_HASH}'"),
            ("accepted_fence_epoch", "INTEGER NOT NULL DEFAULT 0"),
        ),
        "command_results": (("result_bytes", "BLOB"),),
    }
    with _transaction(connection):
        for table, columns in additions.items():
            existing = {
                str(row[1])
                for row in connection.execute(f'PRAGMA table_info("{table}")')
            }
            for name, declaration in columns:
                if name not in existing:
                    connection.execute(
                        f'ALTER TABLE "{table}" ADD COLUMN "{name}" {declaration}'
                    )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS authority_command_journal (
                authority_domain TEXT NOT NULL,
                command_id TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                journal_state TEXT NOT NULL CHECK (
                    journal_state IN (
                        'RECEIVED', 'EFFECT_COMMITTED', 'RESULT_COMMITTED'
                    )
                ),
                semantic_pre_sha256 TEXT NOT NULL,
                semantic_post_sha256 TEXT,
                result_sha256 TEXT,
                last_fence_epoch INTEGER NOT NULL CHECK (last_fence_epoch >= 1),
                received_journal_sha256 TEXT,
                received_snapshot_sha256 TEXT,
                effect_journal_sha256 TEXT,
                effect_snapshot_sha256 TEXT,
                result_journal_sha256 TEXT,
                result_snapshot_sha256 TEXT,
                PRIMARY KEY (authority_domain, command_id),
                FOREIGN KEY (authority_domain, command_id)
                    REFERENCES command_receipts(authority_domain, command_id)
            ) STRICT
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS authority_command_journal_no_delete
            BEFORE DELETE ON authority_command_journal
            BEGIN
                SELECT RAISE(ABORT, 'append_only:authority_command_journal');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS authority_command_journal_legal_update
            BEFORE UPDATE ON authority_command_journal
            WHEN NOT (
                OLD.authority_domain = NEW.authority_domain
                AND OLD.command_id = NEW.command_id
                AND OLD.payload_sha256 = NEW.payload_sha256
                AND OLD.semantic_pre_sha256 = NEW.semantic_pre_sha256
                AND NEW.last_fence_epoch >= OLD.last_fence_epoch
                AND (
                    OLD.journal_state = NEW.journal_state
                    OR (
                        OLD.journal_state = 'RECEIVED'
                        AND NEW.journal_state = 'EFFECT_COMMITTED'
                    )
                    OR (
                        OLD.journal_state = 'EFFECT_COMMITTED'
                        AND NEW.journal_state = 'RESULT_COMMITTED'
                    )
                )
            )
            BEGIN
                SELECT RAISE(ABORT, 'illegal_transition:authority_command_journal');
            END
            """
        )


class _transaction:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def __enter__(self) -> sqlite3.Connection:
        self.connection.execute("BEGIN IMMEDIATE")
        return self.connection

    def __exit__(self, error_type: Any, error: Any, traceback: Any) -> None:
        if error_type is None:
            self.connection.commit()
        else:
            self.connection.rollback()


def _semantic_state_hash(
    connection: sqlite3.Connection,
    domain: AuthorityDomain,
) -> str:
    subject = connection.execute(
        "SELECT lifecycle_state, state_sha256, last_event_id FROM subjects "
        "WHERE subject_type = ? AND subject_id = ?",
        (domain.subject_type, domain.subject_id),
    ).fetchone()
    subject_state = {
        "last_event_id": None if subject is None else subject["last_event_id"],
        "lifecycle_state": "absent" if subject is None else subject["lifecycle_state"],
        "state_sha256": ZERO_HASH if subject is None else subject["state_sha256"],
        "subject_id": domain.subject_id,
        "subject_type": domain.subject_type,
    }
    events = [
        {
            "event_id": row["event_id"],
            "event_sha256": row["event_sha256"],
        }
        for row in connection.execute(
            "SELECT event_id, event_sha256 FROM lifecycle_events "
            "WHERE subject_type = ? AND subject_id = ? ORDER BY rowid",
            (domain.subject_type, domain.subject_id),
        )
    ]
    authorizations: list[dict[str, Any]] = []
    matching_ids: list[str] = []
    for row in connection.execute(
        "SELECT * FROM authorizations ORDER BY authorization_id"
    ):
        raw = bytes(row["canonical_grant"])
        try:
            grant = parse_raw_json(raw)
        except Exception as error:
            raise AuthorityRejection("authorization_store_corrupt") from error
        if not isinstance(grant, dict) or canonicalize(grant) != raw:
            raise AuthorityRejection("authorization_store_corrupt")
        body = grant.get("body")
        if not isinstance(body, dict) or body.get("scope") != domain.authority_domain:
            continue
        authorization_id = str(row["authorization_id"])
        matching_ids.append(authorization_id)
        authorizations.append(
            {
                "authorization_id": authorization_id,
                "decision_sha256": row["decision_sha256"],
                "reusable": bool(row["reusable"]),
                "signer_set_epoch": row["signer_set_epoch"],
                "used_at": row["used_at"],
            }
        )
    revocations = [
        {
            "authorization_id": row["authorization_id"],
            "revocation_sha256": row["revocation_sha256"],
            "revoked_at": row["revoked_at"],
        }
        for row in connection.execute(
            "SELECT authorization_id, revocation_sha256, revoked_at "
            "FROM authorization_revocations ORDER BY authorization_id, revocation_sha256"
        )
        if row["authorization_id"] in matching_ids
    ]
    decisions = [
        {
            "authorization_id": row["authorization_id"],
            "decision_code": row["decision_code"],
            "decision_sha256": row["decision_sha256"],
            "decided_at": row["decided_at"],
        }
        for row in connection.execute(
            "SELECT decision_sha256, authorization_id, decision_code, decided_at "
            "FROM authorization_decisions ORDER BY decision_sha256"
        )
        if row["authorization_id"] in matching_ids
    ]
    proposal_replay = [
        {
            "accepted_at": row["accepted_at"],
            "accepted_sha256": row["accepted_sha256"],
            "proposal_id": row["proposal_id"],
        }
        for row in connection.execute(
            "SELECT proposal_id, accepted_sha256, accepted_at "
            "FROM proposal_replay_ids ORDER BY proposal_id"
        )
    ]
    semantic = {
        "applied_event_prefix": events,
        "authority_domain": domain.authority_domain,
        "authorization_state": {
            "authorizations": authorizations,
            "decisions": decisions,
            "revocations": revocations,
        },
        "proposal_replay_state": proposal_replay,
        "schema_version": "skeleton.authority-semantic-state.v1",
        "subject_states": [subject_state],
    }
    return sha256_hex(canonicalize(semantic))


def _journal_state_hash(
    connection: sqlite3.Connection,
    domain: AuthorityDomain,
) -> str:
    entries: list[dict[str, Any]] = []
    for journal in connection.execute(
        "SELECT * FROM authority_command_journal "
        "WHERE authority_domain = ? ORDER BY command_id",
        (domain.authority_domain,),
    ):
        receipt = connection.execute(
            "SELECT request_sha256, semantic_pre_sha256, accepted_fence_epoch "
            "FROM command_receipts WHERE authority_domain = ? AND command_id = ?",
            (domain.authority_domain, journal["command_id"]),
        ).fetchone()
        effect = connection.execute(
            "SELECT effect_sha256, pre_state_sha256, post_state_sha256, fence_epoch "
            "FROM command_effects WHERE authority_domain = ? AND command_id = ?",
            (domain.authority_domain, journal["command_id"]),
        ).fetchone()
        result = connection.execute(
            "SELECT result_sha256, fence_epoch FROM command_results "
            "WHERE authority_domain = ? AND command_id = ?",
            (domain.authority_domain, journal["command_id"]),
        ).fetchone()
        state = str(journal["journal_state"])
        if receipt is None:
            raise AuthorityRejection("journal_receipt_corrupt")
        if (
            (state == "RECEIVED" and (effect is not None or result is not None))
            or (
                state == "EFFECT_COMMITTED"
                and (effect is None or result is not None)
            )
            or (
                state == "RESULT_COMMITTED"
                and (effect is None or result is None)
            )
            or receipt["request_sha256"] != journal["payload_sha256"]
            or receipt["semantic_pre_sha256"] != journal["semantic_pre_sha256"]
        ):
            raise AuthorityRejection("journal_state_corrupt")
        entries.append(
            {
                "command_id": journal["command_id"],
                "effect": (
                    None
                    if effect is None
                    else {
                        "effect_sha256": effect["effect_sha256"],
                        "fence_epoch": int(effect["fence_epoch"]),
                        "post_state_sha256": effect["post_state_sha256"],
                        "pre_state_sha256": effect["pre_state_sha256"],
                    }
                ),
                "journal_state": state,
                "last_fence_epoch": int(journal["last_fence_epoch"]),
                "payload_sha256": journal["payload_sha256"],
                "receipt": {
                    "accepted_fence_epoch": int(receipt["accepted_fence_epoch"]),
                    "semantic_pre_sha256": receipt["semantic_pre_sha256"],
                },
                "result": (
                    None
                    if result is None
                    else {
                        "fence_epoch": int(result["fence_epoch"]),
                        "result_sha256": result["result_sha256"],
                    }
                ),
                "semantic_post_sha256": journal["semantic_post_sha256"],
            }
        )
    value = {
        "authority_domain": domain.authority_domain,
        "entries": entries,
        "schema_version": "skeleton.authority-journal-state.v1",
    }
    return sha256_hex(canonicalize(value))


def _hashes(
    connection: sqlite3.Connection,
    domain: AuthorityDomain,
) -> AuthorityHashes:
    semantic = _semantic_state_hash(connection, domain)
    journal = _journal_state_hash(connection, domain)
    snapshot = sha256_hex(
        canonicalize(
            {
                "journal_state_sha256": journal,
                "schema_version": "skeleton.authority-snapshot.v1",
                "semantic_state_sha256": semantic,
            }
        )
    )
    return AuthorityHashes(
        semantic_state_sha256=semantic,
        journal_state_sha256=journal,
        authority_snapshot_sha256=snapshot,
    )


def _verify_current_evidence(
    journal: sqlite3.Row | None,
    hashes: AuthorityHashes,
) -> None:
    if journal is None:
        return
    state = journal["journal_state"]
    fields = {
        "RECEIVED": ("received_journal_sha256", "received_snapshot_sha256"),
        "EFFECT_COMMITTED": ("effect_journal_sha256", "effect_snapshot_sha256"),
        "RESULT_COMMITTED": ("result_journal_sha256", "result_snapshot_sha256"),
    }
    if state not in fields:
        raise AuthorityRejection("journal_state_corrupt")
    journal_field, snapshot_field = fields[state]
    if (
        journal[journal_field] != hashes.journal_state_sha256
        or journal[snapshot_field] != hashes.authority_snapshot_sha256
    ):
        raise AuthorityRejection("journal_evidence_corrupt")
    semantic_expected = (
        journal["semantic_pre_sha256"]
        if state == "RECEIVED"
        else journal["semantic_post_sha256"]
    )
    if semantic_expected != hashes.semantic_state_sha256:
        raise AuthorityRejection("semantic_evidence_corrupt")


def _insert_lifecycle_event(
    connection: sqlite3.Connection,
    event: LifecycleEvent,
) -> None:
    try:
        connection.execute(
            """
            INSERT INTO lifecycle_events (
                event_id, subject_type, subject_id, prior_state, new_state,
                prior_state_sha256, event_sha256, cause_code,
                cause_evidence_sha256, authorization_mode,
                authorization_evidence_sha256, occurred_at, canonical_event
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.subject_type,
                event.subject_id,
                event.prior_state,
                event.new_state,
                event.prior_state_sha256,
                event.event_sha256,
                event.cause_code,
                event.cause_evidence_sha256,
                event.authorization_mode,
                event.authorization_evidence_sha256,
                event.occurred_at,
                event.canonical_bytes,
            ),
        )
        connection.execute(
            """
            INSERT INTO subjects(
                subject_type, subject_id, lifecycle_state,
                state_sha256, last_event_id
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(subject_type, subject_id) DO UPDATE SET
                lifecycle_state = excluded.lifecycle_state,
                state_sha256 = excluded.state_sha256,
                last_event_id = excluded.last_event_id
            """,
            (
                event.subject_type,
                event.subject_id,
                event.new_state,
                event.event_sha256,
                event.event_id,
            ),
        )
    except sqlite3.IntegrityError as error:
        raise AuthorityRejection("duplicate_command_effect") from error


def load_result_signer(
    path: Path,
    store: KernelStore,
) -> ResultSigner:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise AuthorityRejection("result_signer_file_invalid")
    raw = resolved.read_bytes()
    if (
        len(raw) != 64
        or any(byte not in b"0123456789abcdef" for byte in raw)
    ):
        raise AuthorityRejection("result_signer_seed_invalid")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw.decode("ascii")))
    except ValueError as error:
        raise AuthorityRejection("result_signer_seed_invalid") from error
    public_key = private_key.public_key().public_bytes_raw()
    key_id = hashlib.sha256(public_key).hexdigest()
    try:
        epoch = store.current_signer_epoch()
        row = store.connection.execute(
            "SELECT public_key FROM signer_set_members "
            "WHERE signer_set_epoch = ? AND key_id = ? AND member_status = 'active'",
            (epoch, key_id),
        ).fetchone()
    except Exception as error:
        raise AuthorityRejection("result_signer_state_absent") from error
    if (
        row is None
        or row["public_key"] != public_key.hex()
        or key_id not in store.active_signer_ids()
    ):
        raise AuthorityRejection("result_signer_inactive")
    return ResultSigner(private_key=private_key, key_id=key_id)


def authority_result_preimage(envelope: Mapping[str, Any]) -> bytes:
    key_id = str(envelope["signer_key_id"]).encode("ascii")
    epoch = str(envelope["signer_set_epoch"]).encode("ascii")
    domain = AUTHORITY_RESULT_DOMAIN.encode("ascii")
    body = canonicalize(envelope["body"])
    return b"".join(
        (
            MAGIC,
            struct.pack(">H", 1),
            bytes((AUTHORITY_RESULT_CLASS_TAG,)),
            struct.pack(">H", len(domain)),
            domain,
            struct.pack(">H", len(key_id)),
            key_id,
            struct.pack(">H", len(epoch)),
            epoch,
            struct.pack(">Q", len(body)),
            body,
        )
    )


def _parse_time(value: str, code: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise AuthorityRejection(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise AuthorityRejection(code) from error
    if parsed.tzinfo != timezone.utc:
        raise AuthorityRejection(code)
    return parsed


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _no_after_commit(_point: str) -> None:
    return
