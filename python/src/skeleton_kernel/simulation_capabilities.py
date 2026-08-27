"""Root-authenticated Phase 9 value capabilities.

The simulator accepts economic inputs only when their complete canonical body is
covered by the independently pinned Phase 6 release root.  A digest-shaped value
is deliberately insufficient: callers can calculate hashes, but they cannot
produce an Ed25519 signature for a different body.
"""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from struct import pack
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .bootstrap_trust import EXPECTED_RELEASE_ROOT_ANCHOR_SHA256
from .canonical import canonicalize, parse_raw_json


AUTHORITY_DOMAIN = "skeleton.phase09.authenticated-input.v1"
AUTHORITY_PROTOCOL_VERSION = 1
PRODUCTION_AUTHORITY_ANCHOR_SHA256 = (
    "0f5d7befbfba75f1469078206fa4abfb6c83e8a68f7ccd4d108b6d011ff739a1"
)
PRODUCTION_AUTHORITY_FINGERPRINT_SHA256 = (
    "1b85c5f29bb4c05995cb2482bb4752ed6ffa588e0c90ed4b82319cdd5fbeb98c"
)
_MAGIC = b"SKELETON-PHASE09-AUTHORITY\x00"


class SimulationCapabilityRejection(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _load_production_authority_root() -> tuple[bytes, str]:
    candidates = tuple(
        parent
        for parent in Path(__file__).resolve().parents
        if (parent / "trust" / "phase06" / "release-root-anchor.json").is_file()
        and (parent / "trust" / "phase09" / "simulation-authority-root.json").is_file()
    )
    if len(candidates) != 1:
        raise SimulationCapabilityRejection("capability_trust_root_unavailable")
    repository_root = candidates[0]
    parent_path = repository_root / "trust" / "phase06" / "release-root-anchor.json"
    anchor_path = repository_root / "trust" / "phase09" / "simulation-authority-root.json"
    for path in (parent_path, anchor_path):
        if not path.is_file() or path.is_symlink():
            raise SimulationCapabilityRejection("capability_trust_root_unavailable")
    parent_raw = parent_path.read_bytes()
    raw = anchor_path.read_bytes()
    if sha256(parent_raw).hexdigest() != EXPECTED_RELEASE_ROOT_ANCHOR_SHA256:
        raise SimulationCapabilityRejection("capability_trust_root_mismatch")
    try:
        value = parse_raw_json(raw)
    except (TypeError, ValueError) as error:
        raise SimulationCapabilityRejection("capability_trust_root_invalid") from error
    canonical = canonicalize(value) if isinstance(value, dict) else b""
    if (
        not isinstance(value, dict)
        or raw not in (canonical + b"\n", canonical + b"\r\n")
        or sha256(canonical).hexdigest() != PRODUCTION_AUTHORITY_ANCHOR_SHA256
    ):
        raise SimulationCapabilityRejection("capability_trust_root_invalid")
    if value != {
        "anchor_id": "phase09-simulation-authority-root",
        "parent_anchor_sha256": EXPECTED_RELEASE_ROOT_ANCHOR_SHA256,
        "root_fingerprint_sha256": PRODUCTION_AUTHORITY_FINGERPRINT_SHA256,
        "root_public_key": "fd7ee43aaa28ea4f9046fb696f854f15f6a363e55733c3be5e8815e2f1fec2e3",
        "schema_version": "skeleton.phase09.simulation-authority-root.v1",
    }:
        raise SimulationCapabilityRejection("capability_trust_root_invalid")
    public_key = bytes.fromhex(str(value["root_public_key"]))
    if sha256(public_key).hexdigest() != PRODUCTION_AUTHORITY_FINGERPRINT_SHA256:
        raise SimulationCapabilityRejection("capability_trust_root_mismatch")
    return public_key, PRODUCTION_AUTHORITY_FINGERPRINT_SHA256


def _load_authority_root() -> tuple[bytes, str]:
    """Runtime seam patched only by the non-installed pytest fixture issuer."""

    return _load_production_authority_root()


def authority_preimage(object_class: str, body: Mapping[str, Any]) -> bytes:
    if not isinstance(object_class, str) or not object_class.isascii() or not object_class:
        raise SimulationCapabilityRejection("capability_class_invalid")
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


def verify_authority_envelope(
    raw: bytes,
    *,
    object_class: str,
    expected_body: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    if not isinstance(raw, bytes):
        raise SimulationCapabilityRejection("capability_bytes_required")
    sys.audit("skeleton.authority.verify", object_class)
    try:
        value = parse_raw_json(raw)
    except (TypeError, ValueError) as error:
        raise SimulationCapabilityRejection("capability_parse_invalid") from error
    if not isinstance(value, dict) or canonicalize(value) != raw:
        raise SimulationCapabilityRejection("capability_noncanonical")
    if set(value) != {
        "body",
        "object_class",
        "signature",
        "signature_domain",
        "signature_protocol_version",
        "signer_key_id",
    }:
        raise SimulationCapabilityRejection("capability_shape_invalid")
    root_public_key, root_fingerprint = _load_authority_root()
    if (
        value.get("signature_protocol_version") != AUTHORITY_PROTOCOL_VERSION
        or value.get("signature_domain") != AUTHORITY_DOMAIN
        or value.get("object_class") != object_class
        or value.get("signer_key_id") != root_fingerprint
    ):
        raise SimulationCapabilityRejection("capability_trust_root_mismatch")
    body = value.get("body")
    signature = value.get("signature")
    if not isinstance(body, dict):
        raise SimulationCapabilityRejection("capability_body_invalid")
    if (
        not isinstance(signature, str)
        or len(signature) != 128
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise SimulationCapabilityRejection("capability_signature_invalid")
    if expected_body is not None and canonicalize(body) != canonicalize(expected_body):
        raise SimulationCapabilityRejection("capability_body_mismatch")
    if sha256(root_public_key).hexdigest() != root_fingerprint:
        raise SimulationCapabilityRejection("capability_trust_root_mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(root_public_key).verify(
            bytes.fromhex(signature), authority_preimage(object_class, body)
        )
    except (InvalidSignature, ValueError) as error:
        raise SimulationCapabilityRejection("capability_signature_invalid") from error
    return body


__all__ = [
    "AUTHORITY_DOMAIN",
    "AUTHORITY_PROTOCOL_VERSION",
    "PRODUCTION_AUTHORITY_ANCHOR_SHA256",
    "PRODUCTION_AUTHORITY_FINGERPRINT_SHA256",
    "SimulationCapabilityRejection",
    "authority_preimage",
    "verify_authority_envelope",
]
