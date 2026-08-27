"""Exact, signed, fail-closed material authorization evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
import sqlite3
from typing import Any, Mapping

from .bootstrap_trust import ReleaseRootAnchor
from .canonical import canonicalize, parse_raw_json, sha256_hex
from .constitution import ConstitutionRejection, verify_current_signer
from .store import KernelStore


AUTHORIZATION_DOMAIN = "skeleton.authority-grant.v1"
AUTHORIZATION_CLASS = "authority_grant"
AUTHORIZATION_CLASS_TAG = 0x02
ZERO_HASH = "0" * 64
REUSABLE_ACTIONS = frozenset({"pause", "resume"})
TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?Z$"
)


@dataclass(slots=True)
class AuthorizationRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


class AuthorizationService:
    """Issue, consume, and revoke grants against the sole active signer epoch."""

    def __init__(self, release_root: ReleaseRootAnchor, store: KernelStore) -> None:
        if not isinstance(release_root, ReleaseRootAnchor):
            raise TypeError("authenticated ReleaseRootAnchor required")
        self._root = release_root
        self._store = store
        self._assert_trust()

    @property
    def store(self) -> KernelStore:
        """Expose the injected writer identity for atomic service composition."""

        return self._store

    def issue(self, envelope: Mapping[str, Any], *, now: str) -> str:
        self._assert_trust()
        now_value = _timestamp(now, "authorization_time_malformed")
        if set(envelope) != {
            "signature_protocol_version",
            "object_class",
            "signature_domain",
            "signer_key_id",
            "signer_set_epoch",
            "body",
            "signature",
        }:
            raise AuthorizationRejection("authorization_envelope_malformed")
        try:
            verify_current_signer(
                envelope,
                self._store,
                expected_object_class=AUTHORIZATION_CLASS,
                expected_domain=AUTHORIZATION_DOMAIN,
                class_tag=AUTHORIZATION_CLASS_TAG,
            )
        except ConstitutionRejection as error:
            raise AuthorizationRejection(error.code) from error
        body = _authorization_body(envelope.get("body"))
        if body["reauthentication_proof_sha256"] == ZERO_HASH:
            raise AuthorizationRejection("reauthentication_required")
        issued_at = _timestamp(body["issued_at"], "authorization_issued_at_malformed")
        expires_at = _timestamp(body["expires_at"], "authorization_expires_at_malformed")
        if issued_at > now_value:
            raise AuthorizationRejection("authorization_not_yet_valid")
        if now_value >= expires_at:
            raise AuthorizationRejection("authorization_expired")
        canonical_grant = canonicalize(dict(envelope))
        decision_sha256 = sha256_hex(canonical_grant)
        reusable = int(body["action"] in REUSABLE_ACTIONS)
        try:
            with self._store.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO authorizations(
                        authorization_id, signer_set_epoch, decision_sha256,
                        canonical_grant, reusable, used_at
                    ) VALUES (?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        body["authorization_id"],
                        envelope["signer_set_epoch"],
                        decision_sha256,
                        canonical_grant,
                        reusable,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO authorization_decisions(
                        decision_sha256, authorization_id, decision_code,
                        canonical_input, decided_at
                    ) VALUES (?, ?, 'issued', ?, ?)
                    """,
                    (
                        decision_sha256,
                        body["authorization_id"],
                        canonical_grant,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise AuthorizationRejection("authorization_replay") from error
        return body["authorization_id"]

    def check(
        self,
        authorization_id: str,
        *,
        action: str,
        scope: str,
        now: str,
    ) -> str:
        self._assert_trust()
        now_value = _timestamp(now, "authorization_time_malformed")
        canonical_input, decision_sha256 = self._prepare_consumption(
            self._store.connection,
            authorization_id,
            action=action,
            scope=scope,
            now=now,
            now_value=now_value,
        )
        try:
            with self._store.transaction() as connection:
                self._write_consumption(
                    connection,
                    authorization_id=authorization_id,
                    now=now,
                    canonical_input=canonical_input,
                    decision_sha256=decision_sha256,
                )
        except sqlite3.IntegrityError as error:
            raise AuthorizationRejection("authorization_decision_replay") from error
        return decision_sha256

    def consume_in_transaction(
        self,
        connection: sqlite3.Connection,
        authorization_id: str,
        *,
        action: str,
        scope: str,
        now: str,
    ) -> str:
        """Consume a grant without changing the caller-owned transaction boundary."""

        self._require_active_store_transaction(connection)
        self._assert_trust()
        now_value = _timestamp(now, "authorization_time_malformed")
        canonical_input, decision_sha256 = self._prepare_consumption(
            connection,
            authorization_id,
            action=action,
            scope=scope,
            now=now,
            now_value=now_value,
        )
        try:
            self._write_consumption(
                connection,
                authorization_id=authorization_id,
                now=now,
                canonical_input=canonical_input,
                decision_sha256=decision_sha256,
            )
        except sqlite3.IntegrityError as error:
            raise AuthorizationRejection("authorization_decision_replay") from error
        return decision_sha256

    def _prepare_consumption(
        self,
        connection: sqlite3.Connection,
        authorization_id: str,
        *,
        action: str,
        scope: str,
        now: str,
        now_value: datetime,
    ) -> tuple[bytes, str]:
        row = connection.execute(
            "SELECT * FROM authorizations WHERE authorization_id = ?",
            (authorization_id,),
        ).fetchone()
        if row is None:
            raise AuthorizationRejection("authorization_not_found")
        if row["signer_set_epoch"] != self._store.current_signer_epoch():
            raise AuthorizationRejection("authorization_signer_epoch_inactive")
        if connection.execute(
            "SELECT 1 FROM authorization_revocations WHERE authorization_id = ?",
            (authorization_id,),
        ).fetchone():
            raise AuthorizationRejection("authorization_revoked")
        grant = parse_raw_json(bytes(row["canonical_grant"]))
        if not isinstance(grant, dict):
            raise AuthorizationRejection("authorization_store_corrupt")
        body = _authorization_body(grant.get("body"))
        if body["authorization_id"] != authorization_id:
            raise AuthorizationRejection("authorization_store_corrupt")
        if body["action"] != action:
            raise AuthorizationRejection("authorization_action_mismatch")
        if body["scope"] != scope:
            raise AuthorizationRejection("authorization_scope_mismatch")
        if body["reauthentication_proof_sha256"] == ZERO_HASH:
            raise AuthorizationRejection("reauthentication_required")
        if now_value >= _timestamp(
            body["expires_at"], "authorization_expires_at_malformed"
        ):
            raise AuthorizationRejection("authorization_expired")
        if row["used_at"] is not None and not row["reusable"]:
            raise AuthorizationRejection("authorization_already_used")
        decision_input = {
            "action": action,
            "authorization_id": authorization_id,
            "scope": scope,
            "signer_set_epoch": row["signer_set_epoch"],
            "used_at": now,
        }
        canonical_input = canonicalize(decision_input)
        decision_sha256 = sha256_hex(canonical_input)
        return canonical_input, decision_sha256

    def _write_consumption(
        self,
        connection: sqlite3.Connection,
        *,
        authorization_id: str,
        now: str,
        canonical_input: bytes,
        decision_sha256: str,
    ) -> None:
        current = connection.execute(
            "SELECT used_at, reusable FROM authorizations "
            "WHERE authorization_id = ?",
            (authorization_id,),
        ).fetchone()
        if current["used_at"] is not None and not current["reusable"]:
            raise AuthorizationRejection("authorization_already_used")
        if not current["reusable"]:
            connection.execute(
                "UPDATE authorizations SET used_at = ? "
                "WHERE authorization_id = ? AND used_at IS NULL",
                (now, authorization_id),
            )
        connection.execute(
            """
            INSERT INTO authorization_decisions(
                decision_sha256, authorization_id, decision_code,
                canonical_input, decided_at
            ) VALUES (?, ?, 'authorized', ?, ?)
            """,
            (decision_sha256, authorization_id, canonical_input, now),
        )

    def _require_active_store_transaction(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        if connection is None:
            raise AuthorizationRejection("authorization_connection_required")
        if connection is not self._store.connection:
            raise AuthorizationRejection("authorization_connection_mismatch")
        try:
            active = connection.in_transaction
        except sqlite3.ProgrammingError as error:
            raise AuthorizationRejection("authorization_connection_closed") from error
        if not active:
            raise AuthorizationRejection("authorization_transaction_required")

    def revoke(
        self,
        authorization_id: str,
        *,
        revocation_sha256: str,
        revoked_at: str,
    ) -> None:
        self._assert_trust()
        _lower_hash(revocation_sha256, "revocation_hash_malformed")
        _timestamp(revoked_at, "revocation_time_malformed")
        if not self._store.connection.execute(
            "SELECT 1 FROM authorizations WHERE authorization_id = ?",
            (authorization_id,),
        ).fetchone():
            raise AuthorizationRejection("authorization_not_found")
        try:
            with self._store.transaction() as connection:
                connection.execute(
                    "INSERT INTO authorization_revocations VALUES (?, ?, ?)",
                    (authorization_id, revocation_sha256, revoked_at),
                )
        except sqlite3.IntegrityError as error:
            raise AuthorizationRejection("authorization_revocation_replay") from error

    def _assert_trust(self) -> None:
        try:
            epoch = self._store.current_signer_epoch()
        except Exception as error:
            raise AuthorizationRejection("trust_state_absent") from error
        row = self._store.connection.execute(
            "SELECT root_fingerprint_sha256 FROM signer_set_epochs "
            "WHERE signer_set_epoch = ?",
            (epoch,),
        ).fetchone()
        if (
            row is None
            or row["root_fingerprint_sha256"] != self._root.root_fingerprint_sha256
        ):
            raise AuthorizationRejection("trust_root_mismatch")


def _authorization_body(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizationRejection("authorization_body_malformed")
    required = {
        "schema_version",
        "authorization_id",
        "subject",
        "action",
        "scope",
        "issued_at",
        "expires_at",
        "reauthentication_proof_sha256",
        "audit_id",
        "reversibility",
    }
    if set(value) != required:
        raise AuthorizationRejection("authorization_body_malformed")
    if value["schema_version"] != "skeleton.material-authorization.body.v1":
        raise AuthorizationRejection("authorization_schema_unknown")
    _lower_hash(value["authorization_id"], "authorization_id_malformed")
    _lower_hash(
        value["reauthentication_proof_sha256"],
        "reauthentication_proof_malformed",
    )
    _lower_hash(value["audit_id"], "audit_id_malformed")
    for field in ("subject", "action", "scope", "reversibility"):
        if not isinstance(value[field], str) or not value[field]:
            raise AuthorizationRejection("authorization_body_malformed")
    return value


def _timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP_PATTERN.fullmatch(value):
        raise AuthorizationRejection(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise AuthorizationRejection(code) from error
    if parsed.tzinfo != timezone.utc:
        raise AuthorizationRejection(code)
    return parsed


def _lower_hash(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AuthorizationRejection(code)
    return value
