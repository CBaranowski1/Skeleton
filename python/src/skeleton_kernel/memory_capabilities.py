"""Phase 6-root-authenticated framed capabilities for Phase 10 memory work."""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from struct import pack
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .bootstrap_trust import load_release_root_anchor
from .canonical import canonicalize, parse_raw_json
from .memory_types import MemoryOperationClass


AUTHORITY_DOMAIN = "skeleton.phase10.memory-authority.v1"
AUTHORITY_PROTOCOL_VERSION = 1
_MAGIC = b"SKELETON-PHASE10-MEMORY-AUTHORITY\x00"
_ADMISSION_SCHEMA_VERSION = "skeleton.phase10.memory-admission-authority.v1"
_OPERATION_SCHEMA_VERSION = "skeleton.phase10.memory-operation-authority.v1"
_ENVELOPE_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-envelope.schema.json"


class MemoryCapabilityRejection(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _load_production_authority_root() -> tuple[bytes, str]:
    try:
        root = load_release_root_anchor()
    except Exception as error:
        raise MemoryCapabilityRejection("capability_trust_root_unavailable") from error
    if sha256(root.root_public_key).hexdigest() != root.root_fingerprint_sha256:
        raise MemoryCapabilityRejection("capability_trust_root_mismatch")
    return root.root_public_key, root.root_fingerprint_sha256


def _load_authority_root() -> tuple[bytes, str]:
    """Production root seam patched only by the non-installed pytest issuer."""

    return _load_production_authority_root()


def authority_preimage(object_class: str, body: Mapping[str, Any]) -> bytes:
    if not isinstance(object_class, str) or not object_class.isascii() or not object_class:
        raise MemoryCapabilityRejection("capability_class_invalid")
    class_bytes = object_class.encode("ascii", errors="strict")
    domain_bytes = AUTHORITY_DOMAIN.encode("ascii", errors="strict")
    body_bytes = canonicalize(body)
    return b"".join(
        (
            _MAGIC,
            pack(">H", AUTHORITY_PROTOCOL_VERSION),
            pack(">H", len(domain_bytes)),
            domain_bytes,
            pack(">H", len(class_bytes)),
            class_bytes,
            pack(">Q", len(body_bytes)),
            body_bytes,
        )
    )


def admission_authority_body(
    raw: bytes, *, schema_id: str, source_event_id: str
) -> Mapping[str, Any]:
    """Bind an admission request to exact bytes without granting hash authority."""

    if not isinstance(raw, bytes):
        raise MemoryCapabilityRejection("capability_bytes_required")
    if schema_id != _ENVELOPE_SCHEMA_ID:
        raise MemoryCapabilityRejection("capability_schema_invalid")
    if (
        not isinstance(source_event_id, str)
        or len(source_event_id) != 64
        or any(character not in "0123456789abcdef" for character in source_event_id)
    ):
        raise MemoryCapabilityRejection("capability_source_event_invalid")
    return {
        "canonical_sha256": sha256(raw).hexdigest(),
        "contract_schema_id": schema_id,
        "operation_class": MemoryOperationClass.ADMISSION.value,
        "schema_version": _ADMISSION_SCHEMA_VERSION,
        "source_event_id": source_event_id,
    }


def operation_authority_body(
    *,
    object_class: MemoryOperationClass,
    operation_id: str,
    subject_id: str,
    canonical_bytes: bytes,
) -> Mapping[str, Any]:
    """Bind one privileged durable operation to its exact sealed result bytes."""

    if not isinstance(object_class, MemoryOperationClass):
        raise MemoryCapabilityRejection("capability_class_invalid")
    for value, code in (
        (operation_id, "capability_operation_invalid"),
        (subject_id, "capability_subject_invalid"),
    ):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise MemoryCapabilityRejection(code)
    if not isinstance(canonical_bytes, bytes):
        raise MemoryCapabilityRejection("capability_bytes_required")
    return {
        "canonical_sha256": sha256(canonical_bytes).hexdigest(),
        "operation_class": object_class.value,
        "operation_id": operation_id,
        "schema_version": _OPERATION_SCHEMA_VERSION,
        "subject_id": subject_id,
    }


def verify_authority_envelope(
    raw: bytes,
    *,
    object_class: MemoryOperationClass,
    expected_body: Mapping[str, Any],
) -> Mapping[str, Any]:
    if not isinstance(raw, bytes):
        raise MemoryCapabilityRejection("capability_bytes_required")
    try:
        value = parse_raw_json(raw)
    except (TypeError, ValueError) as error:
        raise MemoryCapabilityRejection("capability_parse_invalid") from error
    if not isinstance(value, dict) or canonicalize(value) != raw:
        raise MemoryCapabilityRejection("capability_noncanonical")
    if set(value) != {
        "body",
        "object_class",
        "signature",
        "signature_domain",
        "signature_protocol_version",
        "signer_key_id",
    }:
        raise MemoryCapabilityRejection("capability_shape_invalid")
    body = value.get("body")
    signature = value.get("signature")
    if not isinstance(body, dict) or set(body) != set(expected_body):
        raise MemoryCapabilityRejection("capability_body_invalid")
    root_public_key, root_fingerprint = _load_authority_root()
    if (
        value.get("signature_protocol_version") != AUTHORITY_PROTOCOL_VERSION
        or value.get("signature_domain") != AUTHORITY_DOMAIN
        or value.get("object_class") != object_class.value
        or value.get("signer_key_id") != root_fingerprint
        or body.get("operation_class") != object_class.value
        or canonicalize(body) != canonicalize(expected_body)
    ):
        raise MemoryCapabilityRejection("capability_trust_root_mismatch")
    if (
        not isinstance(signature, str)
        or len(signature) != 128
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise MemoryCapabilityRejection("capability_signature_invalid")
    if sha256(root_public_key).hexdigest() != root_fingerprint:
        raise MemoryCapabilityRejection("capability_trust_root_mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(root_public_key).verify(
            bytes.fromhex(signature), authority_preimage(object_class.value, body)
        )
    except (InvalidSignature, ValueError) as error:
        raise MemoryCapabilityRejection("capability_signature_invalid") from error
    return body


__all__ = [
    "AUTHORITY_DOMAIN",
    "AUTHORITY_PROTOCOL_VERSION",
    "MemoryCapabilityRejection",
    "MemoryOperationClass",
    "admission_authority_body",
    "operation_authority_body",
    "authority_preimage",
    "verify_authority_envelope",
]
