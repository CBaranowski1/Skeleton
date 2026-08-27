"""Root-authenticated Constitution and signer-set state transitions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .bootstrap_trust import ReleaseRootAnchor
from .canonical import canonicalize, parse_raw_json, sha256_hex
from .store import KernelStore, StoreRejection


MAGIC = b"SKELETON-SIGNATURE-PREIMAGE\x00"
CONSTITUTION_CLASS_TAG = 0x01
CONSTITUTION_DOMAIN = "skeleton.constitution.v1"
UINT64_MAX = 18_446_744_073_709_551_615
ZERO_HASH = "0" * 64


@dataclass(slots=True)
class ConstitutionRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def build_signature_preimage(envelope: Mapping[str, Any]) -> bytes:
    """Build the exact D-25 preimage without inspecting the signature field."""

    version = envelope.get("signature_protocol_version")
    object_class = envelope.get("object_class")
    domain = envelope.get("signature_domain")
    signer_key_id = envelope.get("signer_key_id")
    epoch = envelope.get("signer_set_epoch")
    body = envelope.get("body")
    if version != 1:
        raise ConstitutionRejection("unknown_signature_protocol")
    if object_class != "constitution":
        raise ConstitutionRejection("cross_class")
    if domain != CONSTITUTION_DOMAIN:
        raise ConstitutionRejection("signature_domain_mismatch")
    key_bytes = _ascii_field(signer_key_id, "malformed_signer_key_id")
    if len(key_bytes) != 64 or any(
        character not in b"0123456789abcdef" for character in key_bytes
    ):
        raise ConstitutionRejection("malformed_signer_key_id")
    epoch_bytes = _canonical_epoch(epoch).encode("ascii")
    domain_bytes = domain.encode("ascii")
    body_bytes = canonicalize(body)
    return b"".join(
        (
            MAGIC,
            struct.pack(">H", version),
            bytes((CONSTITUTION_CLASS_TAG,)),
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


class ConstitutionAuthority:
    """Apply only root-signed exact-next Constitution transitions."""

    def __init__(self, release_root: ReleaseRootAnchor, store: KernelStore) -> None:
        if not isinstance(release_root, ReleaseRootAnchor):
            raise TypeError("authenticated ReleaseRootAnchor required")
        self._root = release_root
        self._store = store

    @property
    def release_root(self) -> ReleaseRootAnchor:
        return self._root

    def apply(self, envelope: Mapping[str, Any]) -> str:
        if set(envelope) != {
            "signature_protocol_version",
            "object_class",
            "signature_domain",
            "signer_key_id",
            "signer_set_epoch",
            "body",
            "signature",
        }:
            raise ConstitutionRejection("invalid_envelope_shape")
        body = envelope.get("body")
        if not isinstance(body, dict):
            raise ConstitutionRejection("invalid_constitution_body")
        root_key_id = self._root.root_fingerprint_sha256
        signer_key_id = envelope.get("signer_key_id")
        if signer_key_id != root_key_id:
            members = body.get("next_signer_set", {}).get("members", [])
            member_ids = {
                member.get("key_id")
                for member in members
                if isinstance(member, dict)
            }
            code = (
                "self_authorization"
                if signer_key_id in member_ids
                else "root_substitution"
            )
            raise ConstitutionRejection(code)
        if envelope.get("signer_set_epoch") != self._root.anchor_epoch:
            raise ConstitutionRejection("root_anchor_epoch_mismatch")
        signature_text = envelope.get("signature")
        if (
            not isinstance(signature_text, str)
            or len(signature_text) != 128
            or any(
                character not in "0123456789abcdef"
                for character in signature_text
            )
        ):
            raise ConstitutionRejection("malformed_signature_wire")
        preimage = build_signature_preimage(envelope)
        try:
            Ed25519PublicKey.from_public_bytes(self._root.root_public_key).verify(
                bytes.fromhex(signature_text),
                preimage,
            )
        except (InvalidSignature, ValueError) as error:
            raise ConstitutionRejection("signature_invalid") from error

        parsed = _parse_constitution_body(body, self._root)
        try:
            self._store.record_signer_set(**parsed)
        except StoreRejection as error:
            mapping = {
                "invalid_signer_genesis": "invalid_genesis",
                "signer_epoch_not_exact_next": "signer_epoch_not_exact_next",
                "signer_ancestry_mismatch": "signer_ancestry_mismatch",
                "signer_transition_replay": "signer_transition_replay",
                "root_fingerprint_mismatch": "root_fingerprint_mismatch",
            }
            raise ConstitutionRejection(mapping.get(error.code, error.code)) from error
        return parsed["constitution_sha256"]


class ConstitutionPolicy:
    """Executable, domain-neutral constitutional prohibition membrane."""

    _PROHIBITIONS = {
        "accept_customer_funds": "policy_third_party_funds",
        "manage_third_party_accounts": "policy_third_party_accounts",
        "publish_paid_advice_or_signals": "policy_external_advice",
        "copy_external_actions": "policy_copy_external_actions",
        "hold_custody": "policy_custody",
        "transfer_third_party_value": "policy_third_party_transfer",
        "execute_sports_contract": "policy_sports_execution",
    }

    def __init__(self, release_root: ReleaseRootAnchor, store: KernelStore) -> None:
        if not isinstance(release_root, ReleaseRootAnchor):
            raise TypeError("authenticated ReleaseRootAnchor required")
        self._root = release_root
        self._store = store
        self._assert_trust()

    def enforce(self, capability: str, *, context: Mapping[str, Any]) -> str:
        self._assert_trust()
        if capability in self._PROHIBITIONS:
            raise ConstitutionRejection(self._PROHIBITIONS[capability])
        if (
            not isinstance(capability, str)
            or not capability
            or not isinstance(context, Mapping)
        ):
            raise ConstitutionRejection("policy_input_malformed")
        decision = {
            "capability": capability,
            "context": dict(context),
            "root_fingerprint_sha256": self._root.root_fingerprint_sha256,
            "signer_set_epoch": self._store.current_signer_epoch(),
        }
        canonical_input = canonicalize(decision)
        decision_sha256 = sha256_hex(canonical_input)
        try:
            with self._store.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO authorization_decisions(
                        decision_sha256, authorization_id, decision_code,
                        canonical_input, decided_at
                    ) VALUES (?, NULL, 'policy_allowed', ?, 'constitutional')
                    """,
                    (decision_sha256, canonical_input),
                )
        except Exception as error:
            raise ConstitutionRejection("policy_decision_persistence_failed") from error
        return decision_sha256

    def _assert_trust(self) -> None:
        try:
            epoch = self._store.current_signer_epoch()
        except StoreRejection as error:
            raise ConstitutionRejection("trust_state_absent") from error
        row = self._store.connection.execute(
            "SELECT root_fingerprint_sha256 FROM signer_set_epochs "
            "WHERE signer_set_epoch = ?",
            (epoch,),
        ).fetchone()
        if (
            row is None
            or row["root_fingerprint_sha256"] != self._root.root_fingerprint_sha256
        ):
            raise ConstitutionRejection("trust_root_mismatch")


def verify_current_signer(
    envelope: Mapping[str, Any],
    store: KernelStore,
    *,
    expected_object_class: str,
    expected_domain: str,
    class_tag: int,
) -> bytes:
    """Verify a new signed object only against the sole current signer set."""

    epoch = _canonical_epoch(envelope.get("signer_set_epoch"))
    if epoch != store.current_signer_epoch():
        raise ConstitutionRejection("signer_epoch_mismatch")
    return _verify_signer_at_epoch(
        envelope,
        store,
        epoch=epoch,
        expected_object_class=expected_object_class,
        expected_domain=expected_domain,
        class_tag=class_tag,
    )


def verify_historical_signer(
    envelope: Mapping[str, Any],
    store: KernelStore,
    *,
    expected_object_class: str,
    expected_domain: str,
    class_tag: int,
) -> bytes:
    """Verify an immutable stored object against its recorded signer epoch."""

    epoch = _canonical_epoch(envelope.get("signer_set_epoch"))
    _verify_signer_ancestry(store, epoch)
    return _verify_signer_at_epoch(
        envelope,
        store,
        epoch=epoch,
        expected_object_class=expected_object_class,
        expected_domain=expected_domain,
        class_tag=class_tag,
    )


def _verify_signer_at_epoch(
    envelope: Mapping[str, Any],
    store: KernelStore,
    *,
    epoch: str,
    expected_object_class: str,
    expected_domain: str,
    class_tag: int,
) -> bytes:
    if envelope.get("signature_protocol_version") != 1:
        raise ConstitutionRejection("unknown_signature_protocol")
    if envelope.get("object_class") != expected_object_class:
        raise ConstitutionRejection("cross_class")
    if envelope.get("signature_domain") != expected_domain:
        raise ConstitutionRejection("signature_domain_mismatch")
    key_id = envelope.get("signer_key_id")
    row = store.connection.execute(
        "SELECT public_key FROM signer_set_members "
        "WHERE signer_set_epoch = ? AND key_id = ? AND member_status = 'active'",
        (epoch, key_id),
    ).fetchone()
    revoked = store.connection.execute(
        "SELECT 1 FROM signer_revocations "
        "WHERE signer_set_epoch = ? AND key_id = ?",
        (epoch, key_id),
    ).fetchone()
    if row is None or revoked is not None:
        raise ConstitutionRejection("signer_inactive")
    signature = envelope.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != 128
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise ConstitutionRejection("malformed_signature_wire")
    domain_bytes = expected_domain.encode("ascii")
    key_bytes = _ascii_field(key_id, "malformed_signer_key_id")
    epoch_bytes = epoch.encode("ascii")
    body_bytes = canonicalize(envelope.get("body"))
    preimage = b"".join(
        (
            MAGIC,
            struct.pack(">H", 1),
            bytes((class_tag,)),
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
    try:
        public_key = bytes.fromhex(row["public_key"])
        if hashlib.sha256(public_key).hexdigest() != key_id:
            raise ConstitutionRejection("signer_key_id_mismatch")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(signature), preimage
        )
    except ConstitutionRejection:
        raise
    except (InvalidSignature, ValueError) as error:
        raise ConstitutionRejection("signature_invalid") from error
    return body_bytes


def _verify_signer_ancestry(store: KernelStore, target_epoch: str) -> None:
    """Require a complete immutable root-consistent chain through the current epoch."""

    current_epoch = store.current_signer_epoch()
    if int(target_epoch) > int(current_epoch):
        raise ConstitutionRejection("signer_epoch_mismatch")
    previous = None
    root_fingerprint = None
    target_found = False
    for epoch_number in range(int(current_epoch) + 1):
        epoch = str(epoch_number)
        row = store.connection.execute(
            "SELECT * FROM signer_set_epochs WHERE signer_set_epoch = ?",
            (epoch,),
        ).fetchone()
        if row is None:
            raise ConstitutionRejection("signer_ancestry_invalid")
        try:
            raw_transition = bytes(row["canonical_transition"])
            transition = parse_raw_json(raw_transition)
        except Exception as error:
            raise ConstitutionRejection("signer_ancestry_invalid") from error
        if (
            not isinstance(transition, dict)
            or canonicalize(transition) != raw_transition
            or transition.get("signer_set_epoch") != epoch
            or transition.get("constitution_epoch") != row["constitution_epoch"]
            or transition.get("constitution_sha256") != row["constitution_sha256"]
            or transition.get("transition_id") != row["transition_id"]
            or transition.get("root_fingerprint_sha256")
            != row["root_fingerprint_sha256"]
            or transition.get("previous_signer_set_epoch")
            != row["previous_signer_set_epoch"]
            or transition.get("previous_constitution_sha256")
            != row["previous_constitution_sha256"]
        ):
            raise ConstitutionRejection("signer_ancestry_invalid")
        if root_fingerprint is None:
            root_fingerprint = row["root_fingerprint_sha256"]
        elif row["root_fingerprint_sha256"] != root_fingerprint:
            raise ConstitutionRejection("root_fingerprint_mismatch")
        if previous is None:
            if (
                row["previous_signer_set_epoch"] is not None
                or row["previous_constitution_sha256"] is not None
            ):
                raise ConstitutionRejection("signer_ancestry_invalid")
        elif (
            row["previous_signer_set_epoch"] != previous["signer_set_epoch"]
            or row["previous_constitution_sha256"]
            != previous["constitution_sha256"]
        ):
            raise ConstitutionRejection("signer_ancestry_invalid")
        if epoch == target_epoch:
            target_found = True
        previous = row
    if not target_found:
        raise ConstitutionRejection("signer_epoch_mismatch")


def _parse_constitution_body(
    body: dict[str, Any],
    root: ReleaseRootAnchor,
) -> dict[str, Any]:
    if body.get("schema_version") != "skeleton.constitution.body.v1":
        raise ConstitutionRejection("unknown_constitution_schema")
    if body.get("release_root_fingerprint_sha256") != root.root_fingerprint_sha256:
        raise ConstitutionRejection("root_fingerprint_mismatch")
    constitution_epoch = _canonical_epoch(body.get("constitution_epoch"))
    previous_epoch = _canonical_epoch(body.get("previous_signer_set_epoch"))
    previous_hash = _lower_hash(
        body.get("previous_constitution_sha256"),
        "previous_constitution_hash_malformed",
    )
    transition_id = body.get("transition_id")
    if not isinstance(transition_id, str) or not transition_id:
        raise ConstitutionRejection("transition_id_malformed")
    next_set = body.get("next_signer_set")
    if not isinstance(next_set, dict) or set(next_set) != {"epoch", "members"}:
        raise ConstitutionRejection("signer_set_malformed")
    signer_epoch = _canonical_epoch(next_set.get("epoch"))
    if signer_epoch != constitution_epoch:
        raise ConstitutionRejection("constitution_signer_epoch_mismatch")
    raw_members = next_set.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        raise ConstitutionRejection("empty_signer_set")
    members: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    revocations: list[str] = []
    active_count = 0
    for member in raw_members:
        if not isinstance(member, dict) or set(member) != {
            "key_id",
            "public_key",
            "status",
        }:
            raise ConstitutionRejection("signer_member_malformed")
        public_key = _lower_hex(member["public_key"], 64, "signer_public_key_malformed")
        key_id = _lower_hash(member["key_id"], "signer_key_id_malformed")
        if hashlib.sha256(bytes.fromhex(public_key)).hexdigest() != key_id:
            raise ConstitutionRejection("signer_key_id_mismatch")
        status = member["status"]
        if status not in {"active", "revoked"}:
            raise ConstitutionRejection("signer_status_unknown")
        if key_id in seen:
            raise ConstitutionRejection("duplicate_signer")
        seen.add(key_id)
        members.append((key_id, public_key, status))
        if status == "revoked":
            revocations.append(key_id)
        else:
            active_count += 1
    if active_count == 0:
        raise ConstitutionRejection("empty_active_signer_set")
    if signer_epoch == "0":
        if previous_epoch != "0" or previous_hash != ZERO_HASH:
            raise ConstitutionRejection("invalid_genesis")
        store_previous_epoch: str | None = None
        store_previous_hash: str | None = None
    else:
        if int(previous_epoch) + 1 != int(signer_epoch):
            raise ConstitutionRejection("signer_epoch_not_exact_next")
        if previous_hash == ZERO_HASH:
            raise ConstitutionRejection("signer_ancestry_mismatch")
        store_previous_epoch = previous_epoch
        store_previous_hash = previous_hash
    return {
        "constitution_sha256": sha256_hex(canonicalize(body)),
        "constitution_epoch": constitution_epoch,
        "signer_set_epoch": signer_epoch,
        "transition_id": transition_id,
        "previous_constitution_sha256": store_previous_hash,
        "previous_signer_set_epoch": store_previous_epoch,
        "root_fingerprint_sha256": root.root_fingerprint_sha256,
        "members": members,
        "revocations": revocations,
    }


def _canonical_epoch(value: Any) -> str:
    if (
        not isinstance(value, str)
        or (value != "0" and (not value.isascii() or not value.isdecimal() or value[0] == "0"))
    ):
        raise ConstitutionRejection("noncanonical_epoch")
    if int(value) > UINT64_MAX:
        raise ConstitutionRejection("epoch_out_of_range")
    return value


def _lower_hash(value: Any, code: str) -> str:
    return _lower_hex(value, 64, code)


def _lower_hex(value: Any, length: int, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ConstitutionRejection(code)
    return value


def _ascii_field(value: Any, code: str) -> bytes:
    if not isinstance(value, str):
        raise ConstitutionRejection(code)
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ConstitutionRejection(code) from error
