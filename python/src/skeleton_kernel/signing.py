"""Exact D-25/D-26 Ed25519 framing for advisory proposals."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import struct
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .bootstrap_trust import (
    EXPECTED_RELEASE_ROOT_ANCHOR_SHA256,
    EXPECTED_RELEASE_ROOT_FINGERPRINT_SHA256,
    ReleaseRootAnchor,
)
from .canonical import canonicalize
from .store import KernelStore, StoreRejection


MAGIC = b"SKELETON-SIGNATURE-PREIMAGE\x00"
SIGNATURE_PROTOCOL_VERSION = 1
ADVISORY_CLASS_TAG = 0x03
ADVISORY_OBJECT_CLASS = "advisory_proposal"
ADVISORY_DOMAIN = "skeleton.advisory-proposal.v1"
UINT16_MAX = 65_535
UINT64_MAX = 18_446_744_073_709_551_615


@dataclass(slots=True)
class SigningRejection(ValueError):
    """Closed signing failure that never contains submitted bytes."""

    code: str

    def __str__(self) -> str:
        return self.code


def derive_key_id(public_key: bytes) -> str:
    """Return the D-26 key ID for one raw 32-byte Ed25519 public key."""

    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise SigningRejection("malformed_public_key")
    return hashlib.sha256(public_key).hexdigest()


def build_advisory_preimage(envelope: Mapping[str, Any]) -> bytes:
    """Build the sole normative D-25 advisory preimage."""

    _validate_header(envelope)
    key_id = _lower_hex(
        envelope.get("signer_key_id"),
        length=64,
        code="malformed_signer_key_id",
    )
    epoch = _canonical_epoch(envelope.get("signer_set_epoch"))
    domain_bytes = ADVISORY_DOMAIN.encode("ascii")
    key_bytes = key_id.encode("ascii")
    epoch_bytes = epoch.encode("ascii")
    body_bytes = canonicalize(envelope.get("body"))
    if (
        len(domain_bytes) > UINT16_MAX
        or len(key_bytes) > UINT16_MAX
        or len(epoch_bytes) > UINT16_MAX
        or len(body_bytes) > UINT64_MAX
    ):
        raise SigningRejection("framing_length_overflow")
    return b"".join(
        (
            MAGIC,
            struct.pack(">H", SIGNATURE_PROTOCOL_VERSION),
            bytes((ADVISORY_CLASS_TAG,)),
            struct.pack(">H", len(domain_bytes)),
            domain_bytes,
            struct.pack(">H", len(key_bytes)),
            key_bytes,
            struct.pack(">H", len(epoch_bytes)),
            epoch_bytes,
            struct.pack(">Q", len(body_bytes)),
            body_bytes,
        )
    )


def sign_advisory_envelope(
    body: Mapping[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    signer_set_epoch: str,
) -> dict[str, Any]:
    """Sign an advisory body at the explicit signer/test-only boundary."""

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Ed25519PrivateKey required at signer boundary")
    public_key = private_key.public_key().public_bytes_raw()
    key_id = derive_key_id(public_key)
    envelope: dict[str, Any] = {
        "signature_protocol_version": SIGNATURE_PROTOCOL_VERSION,
        "object_class": ADVISORY_OBJECT_CLASS,
        "signature_domain": ADVISORY_DOMAIN,
        "signer_key_id": key_id,
        "signer_set_epoch": _canonical_epoch(signer_set_epoch),
        "body": dict(body),
        "signature": "",
    }
    signature = private_key.sign(build_advisory_preimage(envelope))
    if len(signature) != 64:
        raise SigningRejection("signature_length_invalid")
    envelope["signature"] = signature.hex()
    return envelope


def verify_current_advisory_signer(
    envelope: Mapping[str, Any],
    *,
    release_root: ReleaseRootAnchor,
    store: KernelStore,
) -> bytes:
    """Verify only against the active member of the sole current D-27 epoch."""

    _validate_header(envelope)
    key_id = _lower_hex(
        envelope.get("signer_key_id"),
        length=64,
        code="malformed_signer_key_id",
    )
    epoch = _canonical_epoch(envelope.get("signer_set_epoch"))
    signature = _decode_canonical_signature(envelope.get("signature"))
    _assert_release_root(release_root)
    try:
        current_epoch = store.current_signer_epoch()
    except StoreRejection as error:
        raise SigningRejection("signer_state_absent") from error
    if epoch != current_epoch:
        raise SigningRejection("signer_epoch_mismatch")
    epoch_root = store.connection.execute(
        "SELECT root_fingerprint_sha256 FROM signer_set_epochs "
        "WHERE signer_set_epoch = ?",
        (current_epoch,),
    ).fetchone()
    if (
        epoch_root is None
        or epoch_root["root_fingerprint_sha256"]
        != release_root.root_fingerprint_sha256
    ):
        raise SigningRejection("trust_root_mismatch")
    member = store.connection.execute(
        "SELECT public_key, member_status FROM signer_set_members "
        "WHERE signer_set_epoch = ? AND key_id = ?",
        (current_epoch, key_id),
    ).fetchone()
    revoked = store.connection.execute(
        "SELECT 1 FROM signer_revocations "
        "WHERE signer_set_epoch = ? AND key_id = ?",
        (current_epoch, key_id),
    ).fetchone()
    if member is not None and (
        member["member_status"] == "revoked" or revoked is not None
    ):
        raise SigningRejection("signer_revoked")
    if member is None or member["member_status"] != "active":
        raise SigningRejection("signer_inactive")
    public_key_text = _lower_hex(
        member["public_key"],
        length=64,
        code="malformed_public_key",
    )
    public_key = bytes.fromhex(public_key_text)
    if derive_key_id(public_key) != key_id:
        raise SigningRejection("signer_key_id_mismatch")
    preimage = build_advisory_preimage(envelope)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, preimage)
    except (InvalidSignature, ValueError) as error:
        raise SigningRejection("signature_invalid") from error
    return canonicalize(envelope.get("body"))


def _assert_release_root(release_root: ReleaseRootAnchor) -> None:
    if not isinstance(release_root, ReleaseRootAnchor):
        raise SigningRejection("authenticated_release_root_required")
    if (
        release_root.anchor_epoch != "0"
        or release_root.artifact_sha256 != EXPECTED_RELEASE_ROOT_ANCHOR_SHA256
        or release_root.root_fingerprint_sha256
        != EXPECTED_RELEASE_ROOT_FINGERPRINT_SHA256
        or len(release_root.root_public_key) != 32
        or hashlib.sha256(release_root.root_public_key).hexdigest()
        != EXPECTED_RELEASE_ROOT_FINGERPRINT_SHA256
    ):
        raise SigningRejection("trust_root_mismatch")


def _validate_header(envelope: Mapping[str, Any]) -> None:
    if not isinstance(envelope, Mapping):
        raise SigningRejection("invalid_envelope_shape")
    if envelope.get("signature_protocol_version") != SIGNATURE_PROTOCOL_VERSION:
        raise SigningRejection("unknown_signature_protocol")
    if (
        envelope.get("object_class") != ADVISORY_OBJECT_CLASS
        or envelope.get("signature_domain") != ADVISORY_DOMAIN
    ):
        raise SigningRejection("cross_class")


def _decode_canonical_signature(value: Any) -> bytes:
    text = _lower_hex(value, length=128, code="malformed_signature_wire")
    try:
        decoded = bytes.fromhex(text)
    except ValueError as error:
        raise SigningRejection("malformed_signature_wire") from error
    if decoded.hex() != text or len(decoded) != 64:
        raise SigningRejection("malformed_signature_wire")
    return decoded


def _canonical_epoch(value: Any) -> str:
    if (
        not isinstance(value, str)
        or (
            value != "0"
            and (
                not value.isascii()
                or not value.isdecimal()
                or value.startswith("0")
            )
        )
    ):
        raise SigningRejection("noncanonical_epoch")
    if int(value) > UINT64_MAX:
        raise SigningRejection("epoch_out_of_range")
    return value


def _lower_hex(value: Any, *, length: int, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SigningRejection(code)
    return value
