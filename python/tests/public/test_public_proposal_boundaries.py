from __future__ import annotations

import inspect
import json
from pathlib import Path
import sys
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "python" / "src"))

from skeleton_kernel.membrane import ProposalMembrane, VALIDATION_ORDER
from skeleton_kernel.proposal import (
    ProposalRejection,
    assert_proposal_fresh,
    parse_proposal_wire,
)
from skeleton_kernel.proposal_outbox import ProposalOutbox
from skeleton_kernel.schema_registry import SchemaRegistry
from skeleton_kernel.signing import (
    ADVISORY_CLASS_TAG,
    ADVISORY_DOMAIN,
    MAGIC,
    build_advisory_preimage,
    derive_key_id,
    sign_advisory_envelope,
)


CONTRACTS_ROOT = REPO_ROOT / "contracts" / "v1"
RFC8032_SIGNER_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f"
    "5b8a319f35aba624da8cf6ed4fb8a6fb"
)


def _fixture(identifier: str) -> dict[str, Any]:
    fixture_path = CONTRACTS_ROOT / "fixtures" / "envelope-fixtures.jsonl"
    for line in fixture_path.read_bytes().splitlines():
        record = json.loads(line)
        if record["id"] == identifier:
            return record
    raise AssertionError(f"fixture not found: {identifier}")


@pytest.fixture
def registry() -> SchemaRegistry:
    return SchemaRegistry(CONTRACTS_ROOT)


def test_public_signature_preimage_matches_known_answer() -> None:
    fixture = _fixture("proposal-d28-valid")
    envelope = fixture["payload"]
    known = fixture["known_answer"]

    assert MAGIC == b"SKELETON-SIGNATURE-PREIMAGE\x00"
    assert ADVISORY_CLASS_TAG == 0x03
    assert ADVISORY_DOMAIN == "skeleton.advisory-proposal.v1"
    assert build_advisory_preimage(envelope).hex() == known["preimage_hex"]
    assert derive_key_id(bytes.fromhex(known["public_key"])) == known["signer_key_id"]


def test_public_raw_ed25519_signer_boundary() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    body = json.loads(json.dumps(_fixture("proposal-d28-valid")["payload"]["body"]))
    signed = sign_advisory_envelope(
        body,
        private_key=Ed25519PrivateKey.from_private_bytes(RFC8032_SIGNER_SEED),
        signer_set_epoch="0",
    )

    assert len(signed["signature"]) == 128
    assert signed["signature"] == signed["signature"].lower()
    assert signed["signer_key_id"] == (
        "39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f"
    )


def test_public_expiry_and_future_creation_reject(registry: SchemaRegistry) -> None:
    raw = json.dumps(
        _fixture("proposal-d28-valid")["payload"],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    proposal = parse_proposal_wire(raw, registry=registry)

    assert_proposal_fresh(proposal, now="2026-07-28T16:01:00Z")
    with pytest.raises(ProposalRejection, match="proposal_expired"):
        assert_proposal_fresh(proposal, now="2026-07-28T16:06:00Z")
    with pytest.raises(ProposalRejection, match="proposal_not_yet_valid"):
        assert_proposal_fresh(proposal, now="2026-07-28T16:00:59Z")


def test_public_noncanonical_wire_rejects(registry: SchemaRegistry) -> None:
    raw = json.dumps(
        _fixture("proposal-d28-valid")["payload"],
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    with pytest.raises(ProposalRejection) as caught:
        parse_proposal_wire(raw, registry=registry)
    assert caught.value.code == "noncanonical_proposal_wire"


def test_public_outbox_has_no_command_or_response_channel() -> None:
    public = {
        name
        for name, member in inspect.getmembers(ProposalOutbox)
        if callable(member) and not name.startswith("_")
    }
    assert public == {"publish"}


def test_public_membrane_validation_order_is_fixed() -> None:
    assert VALIDATION_ORDER == (
        "schema_protocol_wire",
        "root_signer",
        "signature",
        "expiry",
        "replay",
        "provenance",
        "command_free",
        "accepted",
    )


def test_public_membrane_api_accepts_no_root_substitute() -> None:
    forbidden = {
        "anchor_path",
        "binding_path",
        "digest",
        "expected_digest",
        "fingerprint",
        "public_key",
        "root_key",
        "class_tag",
        "signature_domain",
    }
    assert forbidden.isdisjoint(inspect.signature(ProposalMembrane).parameters)
