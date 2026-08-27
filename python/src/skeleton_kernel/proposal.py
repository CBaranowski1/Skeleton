"""Strict D-26 proposal wire parsing and durable replay registration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import re
import sqlite3
from types import MappingProxyType
from typing import Any

from jsonschema.exceptions import ValidationError

from .canonical import (
    CanonicalizationError,
    JSONValue,
    canonicalize,
    parse_raw_json,
    sha256_hex,
)
from .models import SchemaId
from .schema_registry import SchemaRegistry
from .signing import (
    ADVISORY_DOMAIN,
    ADVISORY_OBJECT_CLASS,
    SIGNATURE_PROTOCOL_VERSION,
)
from .store import KernelStore


MAX_PROPOSAL_WIRE_BYTES = 2 * 1024 * 1024
_NORMALIZED_TIMESTAMP = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?Z$"
)


@dataclass(slots=True)
class ProposalRejection(ValueError):
    """Stable proposal failure without submitted-payload echo."""

    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class ValidatedProposal:
    """Immutable schema-valid, exact-canonical advisory wire."""

    wire_bytes: bytes
    wire_sha256: str
    proposal_id: str
    signer_key_id: str
    signer_set_epoch: str
    body_bytes: bytes
    envelope: Mapping[str, Any]
    body: Mapping[str, Any]


def parse_proposal_wire(
    raw: bytes,
    *,
    registry: SchemaRegistry,
) -> ValidatedProposal:
    """Parse only exact canonical D-26 proposal bytes."""

    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PROPOSAL_WIRE_BYTES:
        raise ProposalRejection("proposal_wire_length_invalid")
    if not isinstance(registry, SchemaRegistry):
        raise TypeError("authenticated SchemaRegistry required")
    try:
        value = parse_raw_json(raw)
        if not isinstance(value, dict):
            raise ProposalRejection("invalid_envelope_shape")
        canonical = canonicalize(value)
        if canonical != raw:
            raise ProposalRejection("noncanonical_proposal_wire")
        _validate_envelope_header(value)
        if _contains_forbidden_authority_key(value):
            raise ProposalRejection("command_forbidden")
        validated = registry.validate_raw(raw, SchemaId.ADVISORY_PROPOSAL.value)
    except ProposalRejection:
        raise
    except CanonicalizationError as error:
        raise ProposalRejection("malformed_proposal_wire") from error
    except ValidationError as error:
        raise ProposalRejection("schema_invalid") from error
    body = validated.value.get("body")
    if not isinstance(body, dict):
        raise ProposalRejection("schema_invalid")
    proposal_id = body.get("proposal_id")
    signer_key_id = validated.value.get("signer_key_id")
    signer_set_epoch = validated.value.get("signer_set_epoch")
    if not all(
        isinstance(item, str)
        for item in (proposal_id, signer_key_id, signer_set_epoch)
    ):
        raise ProposalRejection("schema_invalid")
    frozen_envelope = _freeze(validated.value)
    frozen_body = _freeze(body)
    if not isinstance(frozen_envelope, Mapping) or not isinstance(
        frozen_body, Mapping
    ):
        raise ProposalRejection("schema_invalid")
    return ValidatedProposal(
        wire_bytes=raw,
        wire_sha256=sha256_hex(raw),
        proposal_id=proposal_id,
        signer_key_id=signer_key_id,
        signer_set_epoch=signer_set_epoch,
        body_bytes=canonicalize(body),
        envelope=frozen_envelope,
        body=frozen_body,
    )


def register_proposal_replay(
    store: KernelStore,
    proposal: ValidatedProposal,
    *,
    accepted_at: str,
) -> None:
    """Atomically register an accepted proposal ID exactly once."""

    if not isinstance(store, KernelStore):
        raise TypeError("KernelStore required")
    if not isinstance(proposal, ValidatedProposal):
        raise TypeError("ValidatedProposal required")
    if not isinstance(accepted_at, str) or not accepted_at.endswith("Z"):
        raise ProposalRejection("accepted_at_invalid")
    try:
        with store.transaction() as connection:
            connection.execute(
                "INSERT INTO proposal_replay_ids VALUES (?, ?, ?)",
                (
                    proposal.proposal_id,
                    proposal.wire_sha256,
                    accepted_at,
                ),
            )
    except sqlite3.IntegrityError as error:
        raise ProposalRejection("proposal_replay") from error


def assert_proposal_fresh(
    proposal: ValidatedProposal,
    *,
    now: str,
) -> None:
    """Require a normalized creation/expiry interval containing ``now``."""

    if not isinstance(proposal, ValidatedProposal):
        raise TypeError("ValidatedProposal required")
    created_text = proposal.body.get("created_at")
    expires_text = proposal.body.get("expires_at")
    created = _parse_timestamp(created_text, "proposal_created_at_invalid")
    expires = _parse_timestamp(expires_text, "proposal_expires_at_invalid")
    observed = _parse_timestamp(now, "proposal_now_invalid")
    if created >= expires:
        raise ProposalRejection("proposal_time_invalid")
    if observed < created:
        raise ProposalRejection("proposal_not_yet_valid")
    if observed >= expires:
        raise ProposalRejection("proposal_expired")


def _freeze(value: JSONValue) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _parse_timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or _NORMALIZED_TIMESTAMP.fullmatch(value) is None:
        raise ProposalRejection(code)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ProposalRejection(code) from error


def _validate_envelope_header(value: Mapping[str, Any]) -> None:
    if value.get("signature_protocol_version") != SIGNATURE_PROTOCOL_VERSION:
        raise ProposalRejection("unknown_signature_protocol")
    if (
        value.get("object_class") != ADVISORY_OBJECT_CLASS
        or value.get("signature_domain") != ADVISORY_DOMAIN
    ):
        raise ProposalRejection("cross_class")
    key_id = value.get("signer_key_id")
    if (
        not isinstance(key_id, str)
        or len(key_id) != 64
        or any(character not in "0123456789abcdef" for character in key_id)
    ):
        raise ProposalRejection("malformed_signer_key_id")
    epoch = value.get("signer_set_epoch")
    if (
        not isinstance(epoch, str)
        or (
            epoch != "0"
            and (
                not epoch.isascii()
                or not epoch.isdecimal()
                or epoch.startswith("0")
            )
        )
    ):
        raise ProposalRejection("noncanonical_epoch")
    signature = value.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != 128
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise ProposalRejection("malformed_signature_wire")
    try:
        decoded = bytes.fromhex(signature)
    except ValueError as error:
        raise ProposalRejection("malformed_signature_wire") from error
    if len(decoded) != 64 or decoded.hex() != signature:
        raise ProposalRejection("malformed_signature_wire")


def _contains_forbidden_authority_key(value: Any) -> bool:
    forbidden = {
        "account",
        "action",
        "authority_command",
        "broker",
        "command",
        "credential",
        "effect",
        "executable",
        "mutation",
        "target_account",
    }
    if isinstance(value, Mapping):
        return any(
            key in forbidden or _contains_forbidden_authority_key(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_forbidden_authority_key(item) for item in value)
    return False
