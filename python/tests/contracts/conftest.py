from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
import jcs
from jsonschema import Draft202012Validator
from referencing import Registry, Resource


SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
BUNDLE_SCHEMA_VERSION = "skeleton.contract-bundle.v1"


def _contained_path(root: Path, relative_path: str) -> Path:
    if not relative_path or "\\" in relative_path:
        raise ValueError(f"non-canonical bundle path: {relative_path!r}")
    candidate = (root / relative_path).resolve(strict=True)
    resolved_root = root.resolve(strict=True)
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError(f"bundle path escapes contracts root: {relative_path!r}")
    return candidate


def verify_sha256(raw: bytes, expected_sha256: str) -> None:
    observed = hashlib.sha256(raw).hexdigest()
    if observed != expected_sha256:
        raise ValueError(
            f"sha256 mismatch: expected {expected_sha256}, observed {observed}"
        )


def strict_json_loads(raw: bytes) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member: {key}")
            result[key] = value
        return result

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-I-JSON numeric token: {value}")
        ),
    )


def _reject_non_ijson(value: Any) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise ValueError("JSON integer exceeds the exact binary64 safe range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("lone surrogate is outside the I-JSON subset")
        return
    if isinstance(value, list):
        for item in value:
            _reject_non_ijson(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object names must be strings")
            _reject_non_ijson(key)
            _reject_non_ijson(item)
        return
    raise ValueError(f"unsupported I-JSON value: {type(value).__name__}")


def load_bundle(contracts_root: Path) -> dict[str, Any]:
    manifest_path = contracts_root / "bundle-manifest.json"
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw.decode("utf-8"))
    if manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise ValueError("unknown contract bundle schema version")
    if manifest.get("bundle_version") != "1":
        raise ValueError("unknown contract bundle version")
    entries = manifest.get("schemas")
    if not isinstance(entries, list) or not entries:
        raise ValueError("contract bundle must contain schemas")
    paths = [entry.get("path") for entry in entries]
    schema_ids = [entry.get("schema_id") for entry in entries]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ValueError("bundle schema paths must be sorted and unique")
    if len(schema_ids) != len(set(schema_ids)):
        raise ValueError("bundle schema IDs must be unique")
    return manifest


def load_schema_bundle(
    contracts_root: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], Registry[Any]]:
    manifest = load_bundle(contracts_root)
    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    for entry in manifest["schemas"]:
        schema_id = entry["schema_id"]
        schema_path = _contained_path(contracts_root, entry["path"])
        raw = schema_path.read_bytes()
        verify_sha256(raw, entry["sha256"])
        schema = json.loads(raw.decode("utf-8"))
        if schema.get("$schema") != SCHEMA_DRAFT or schema.get("$id") != schema_id:
            raise ValueError(f"schema identity mismatch for {entry['path']}")
        Draft202012Validator.check_schema(schema)
        schemas[schema_id] = schema
        resources.append((schema_id, Resource.from_contents(schema)))
    return manifest, schemas, Registry().with_resources(resources)


def load_core_fixture_records(contracts_root: Path) -> list[dict[str, Any]]:
    manifest = load_bundle(contracts_root)
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list):
        raise ValueError("contract bundle fixtures must be a list")
    entry = next(
        (
            candidate
            for candidate in fixtures
            if candidate.get("path") == "fixtures/core-fixtures.jsonl"
        ),
        None,
    )
    if entry is None:
        raise ValueError("core fixture corpus is not registered")
    fixture_path = _contained_path(contracts_root, entry["path"])
    raw = fixture_path.read_bytes()
    verify_sha256(raw, entry["sha256"])
    lines = raw.splitlines()
    if len(lines) != entry["record_count"]:
        raise ValueError("core fixture record count mismatch")
    records: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        record = strict_json_loads(line)
        identifier = record.get("id")
        if not isinstance(identifier, str) or identifier in identifiers:
            raise ValueError(f"invalid or duplicate fixture ID at line {line_number}")
        identifiers.add(identifier)
        payload = record.get("payload")
        _reject_non_ijson(payload)
        canonical_payload = jcs.canonicalize(payload)
        verify_sha256(canonical_payload, record["source_sha256"])
        records.append(record)
    if [record["id"] for record in records] != sorted(identifiers):
        raise ValueError("core fixture records must be sorted by ID")
    return records


def validate_instance(
    instance: Any,
    schema_id: str,
    schemas: Mapping[str, dict[str, Any]],
    registry: Registry[Any],
) -> None:
    _reject_non_ijson(instance)
    Draft202012Validator(schemas[schema_id], registry=registry).validate(instance)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


@pytest.fixture(scope="session")
def contracts_root(repo_root: Path) -> Path:
    return repo_root / "contracts" / "v1"


@pytest.fixture(scope="session")
def schema_bundle(
    contracts_root: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], Registry[Any]]:
    return load_schema_bundle(contracts_root)
