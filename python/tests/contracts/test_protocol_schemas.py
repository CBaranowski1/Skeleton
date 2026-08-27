from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import jcs
import pytest
from jsonschema import ValidationError

from conftest import strict_json_loads, validate_instance, verify_sha256


COMMAND_ID = "https://schemas.skeleton.local/v1/authority-command.schema.json"
RESULT_ID = "https://schemas.skeleton.local/v1/authority-result.schema.json"
GRANT_ID = "https://schemas.skeleton.local/v1/material-authorization.schema.json"
STATUS_ID = "https://schemas.skeleton.local/v1/kernel-status.schema.json"
SIGNER_PUBLIC_KEY = (
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
SIGNER_KEY_ID = hashlib.sha256(bytes.fromhex(SIGNER_PUBLIC_KEY)).hexdigest()


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def valid_authority_command() -> dict[str, Any]:
    return {
        "schema_version": "skeleton.authority-command.v1",
        "authority_domain": "owner.project",
        "command_id": _sha("command-1"),
        "expected_state_sha256": _sha("state-before"),
        "lifecycle_effect": "activate",
        "authorization_id": _sha("authorization-1"),
        "requested_at": "2026-07-28T17:00:00Z",
    }


def valid_authority_result() -> dict[str, Any]:
    return {
        "signature_protocol_version": 1,
        "object_class": "authority_result",
        "signature_domain": "skeleton.authority-result.v1",
        "signer_key_id": SIGNER_KEY_ID,
        "signer_set_epoch": "0",
        "body": {
            "schema_version": "skeleton.authority-result.body.v1",
            "authority_domain": "owner.project",
            "command_id": _sha("command-1"),
            "disposition": "committed",
            "state_before_sha256": _sha("state-before"),
            "state_after_sha256": _sha("state-after"),
            "event_id": _sha("event-1"),
            "completed_at": "2026-07-28T17:00:01Z",
        },
        "signature": "00" * 64,
    }


def valid_material_authorization() -> dict[str, Any]:
    return {
        "signature_protocol_version": 1,
        "object_class": "authority_grant",
        "signature_domain": "skeleton.authority-grant.v1",
        "signer_key_id": SIGNER_KEY_ID,
        "signer_set_epoch": "0",
        "body": {
            "schema_version": "skeleton.material-authorization.body.v1",
            "authorization_id": _sha("authorization-1"),
            "subject": "owner.primary",
            "action": "activate",
            "scope": "project.alpha",
            "issued_at": "2026-07-28T16:59:00Z",
            "expires_at": "2026-07-28T17:04:00Z",
            "reauthentication_proof_sha256": _sha("reauth-proof"),
            "audit_id": _sha("audit-1"),
            "reversibility": "reversible",
        },
        "signature": "00" * 64,
    }


def valid_kernel_status() -> dict[str, Any]:
    return {
        "schema_version": "skeleton.kernel-status.v1",
        "product_identity": "skeleton.private-single-owner",
        "bundle_sha256": _sha("bundle"),
        "semantic_state_hash": _sha("semantic"),
        "journal_state_hash": _sha("journal"),
        "authority_snapshot_hash": _sha("snapshot"),
        "incomplete_journal_disposition": "idle",
        "authority_process_health": "available",
        "cognition_process_health": "unavailable",
        "lobe_count": 0,
        "capabilities": [],
        "observed_at": "2026-07-28T17:00:02Z",
    }


def _validate(bundle: tuple[Any, Any, Any], schema_id: str, value: Any) -> None:
    _, schemas, registry = bundle
    validate_instance(value, schema_id, schemas, registry)


def test_authority_command_and_result_form_one_idempotent_generic_exchange(
    schema_bundle: tuple[Any, Any, Any],
) -> None:
    command = valid_authority_command()
    result = valid_authority_result()
    _validate(schema_bundle, COMMAND_ID, command)
    _validate(schema_bundle, RESULT_ID, result)
    assert command["command_id"] == result["body"]["command_id"]
    assert command["expected_state_sha256"] == result["body"]["state_before_sha256"]


@pytest.mark.parametrize(
    ("schema_id", "factory", "path", "value"),
    [
        (COMMAND_ID, valid_authority_command, ("command_id",), None),
        (COMMAND_ID, valid_authority_command, ("expected_state_sha256",), None),
        (RESULT_ID, valid_authority_result, ("signature_protocol_version",), 2),
        (RESULT_ID, valid_authority_result, ("object_class",), "authority_grant"),
        (RESULT_ID, valid_authority_result, ("signature_domain",), "skeleton.authority-grant.v1"),
        (RESULT_ID, valid_authority_result, ("signer_key_id",), SIGNER_KEY_ID.upper()),
        (RESULT_ID, valid_authority_result, ("signer_set_epoch",), "00"),
        (RESULT_ID, valid_authority_result, ("signature",), "AA" * 64),
        (RESULT_ID, valid_authority_result, ("signature",), "00" * 63),
    ],
)
def test_authority_protocol_rejects_partial_cross_class_and_noncanonical_wire(
    schema_bundle: tuple[Any, Any, Any],
    schema_id: str,
    factory: Any,
    path: tuple[str, ...],
    value: Any,
) -> None:
    hostile = factory()
    target: Any = hostile
    for part in path[:-1]:
        target = target[part]
    if value is None:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    with pytest.raises(ValidationError):
        _validate(schema_bundle, schema_id, hostile)


def test_authority_schemas_have_no_trading_specific_property_names(
    contracts_root: Path,
) -> None:
    forbidden = {"account", "broker", "order", "position", "trade", "trading"}
    for name in ("authority-command.schema.json", "authority-result.schema.json"):
        schema = json.loads((contracts_root / "schemas" / name).read_text("utf-8"))
        property_names: set[str] = set()

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                properties = value.get("properties")
                if isinstance(properties, dict):
                    property_names.update(properties)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(schema)
        assert not (property_names & forbidden)


def test_material_authorization_is_exact_expiring_audited_and_reauthenticated(
    schema_bundle: tuple[Any, Any, Any],
) -> None:
    grant = valid_material_authorization()
    _validate(schema_bundle, GRANT_ID, grant)
    for field in (
        "subject",
        "action",
        "scope",
        "issued_at",
        "expires_at",
        "reauthentication_proof_sha256",
        "audit_id",
        "reversibility",
    ):
        hostile = copy.deepcopy(grant)
        del hostile["body"][field]
        with pytest.raises(ValidationError):
            _validate(schema_bundle, GRANT_ID, hostile)


def test_material_authorization_rejects_cross_class_and_noncanonical_wire(
    schema_bundle: tuple[Any, Any, Any],
) -> None:
    for field, value in (
        ("object_class", "authority_result"),
        ("signature_domain", "skeleton.authority-result.v1"),
        ("signer_set_epoch", "00"),
        ("signature", "AA" * 64),
    ):
        hostile = valid_material_authorization()
        hostile[field] = value
        with pytest.raises(ValidationError):
            _validate(schema_bundle, GRANT_ID, hostile)


def test_kernel_status_truthfully_allows_zero_lobes_and_cognition_off(
    schema_bundle: tuple[Any, Any, Any],
) -> None:
    status = valid_kernel_status()
    _validate(schema_bundle, STATUS_ID, status)
    assert status["lobe_count"] == 0
    assert status["cognition_process_health"] == "unavailable"
    for field in (
        "bundle_sha256",
        "semantic_state_hash",
        "journal_state_hash",
        "authority_snapshot_hash",
        "incomplete_journal_disposition",
        "authority_process_health",
    ):
        hostile = copy.deepcopy(status)
        del hostile[field]
        with pytest.raises(ValidationError):
            _validate(schema_bundle, STATUS_ID, hostile)


def test_protocol_fixtures_freeze_public_d28_grant_and_result_answers(
    contracts_root: Path,
) -> None:
    records = [
        strict_json_loads(line)
        for line in (contracts_root / "fixtures" / "protocol-fixtures.jsonl")
        .read_bytes()
        .splitlines()
    ]
    assert [record["id"] for record in records] == sorted(
        record["id"] for record in records
    )
    required = {
        "authority-grant-d28-valid",
        "authority-grant-d28-signature-mutation",
        "authority-grant-d28-malformed-wire",
        "authority-result-d28-valid",
        "authority-result-d28-cross-class",
        "authority-result-d28-inactive-epoch",
        "authority-result-d28-revoked-signer",
        "authority-command-valid",
        "kernel-status-zero-lobes",
    }
    assert {record["id"] for record in records} == required
    for record in records:
        verify_sha256(jcs.canonicalize(record["payload"]), record["source_sha256"])
        known = record.get("known_answer")
        if known:
            assert known["key_material_scope"] == "public_test_only"
            assert known["body_jcs_hex"] == jcs.canonicalize(
                record["payload"]["body"]
            ).hex()
            assert len(bytes.fromhex(known["preimage_hex"])) > 32
            assert known["signature"] == record["payload"]["signature"]


def test_index_covers_protocol_and_jcs_sources_exactly(contracts_root: Path) -> None:
    index = strict_json_loads((contracts_root / "fixture-index.json").read_bytes())
    paths = [source["path"] for source in index["sources"]]
    assert paths == sorted(paths)
    required_paths = {
        "fixtures/protocol-fixtures.jsonl",
        "fixtures/jcs-rfc8785-vectors.jsonl",
    }
    selected_sources = [
        source for source in index["sources"] if source["path"] in required_paths
    ]
    assert {source["path"] for source in selected_sources} == required_paths
    for source in selected_sources:
        path = contracts_root / source["path"]
        verify_sha256(path.read_bytes(), source["sha256"])
        assert source["record_count"] == len(source["cases"])


def test_indexed_jcs_vectors_freeze_exact_bytes_and_fail_closed(
    contracts_root: Path,
) -> None:
    records = [
        strict_json_loads(line)
        for line in (contracts_root / "fixtures" / "jcs-rfc8785-vectors.jsonl")
        .read_bytes()
        .splitlines()
    ]
    ids = {record["id"] for record in records}
    assert {
        "jcs-non-bmp-utf16-order",
        "jcs-minus-zero",
        "jcs-binary64-edge",
        "jcs-escapes-solidus",
        "jcs-valid-nonnormalized-unicode",
        "jcs-invalid-utf8",
        "jcs-lone-surrogate",
        "jcs-duplicate-member",
        "jcs-no-final-newline",
    } <= ids
    for record in records:
        assert record["source_sha256"] == hashlib.sha256(
            bytes.fromhex(record["raw_input_hex"])
        ).hexdigest()
        if record["expected_verdict"] == "accept":
            assert not bytes.fromhex(record["canonical_utf8_hex"]).endswith(b"\n")
        else:
            assert record["rejection_code"]


def test_release_root_anchor_is_exact_independent_artifact(
    repo_root: Path,
    contracts_root: Path,
) -> None:
    anchor = repo_root / "trust" / "phase06" / "release-root-anchor.json"
    raw = anchor.read_bytes()
    assert len(raw) == 297
    assert hashlib.sha256(raw).hexdigest() == (
        "56dbeb400d868d747728101f7356259f4802b7165c129180adf902934d2e02ed"
    )
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert not raw.endswith(b"\n")
    parsed = strict_json_loads(raw)
    assert parsed["anchor_epoch"] == "0"
    assert hashlib.sha256(bytes.fromhex(parsed["root_public_key"])).hexdigest() == (
        "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
    )
    manifest_raw = (contracts_root / "bundle-manifest.json").read_bytes()
    index_raw = (contracts_root / "fixture-index.json").read_bytes()
    assert b"release-root-anchor" not in manifest_raw
    assert b"release-root-anchor" not in index_raw
