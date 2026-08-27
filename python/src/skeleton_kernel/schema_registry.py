"""Authenticated, offline JSON Schema bundle registry."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .canonical import (
    JSONValue,
    canonicalize,
    parse_raw_json,
    sha256_hex,
)


SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
BUNDLE_SCHEMA_VERSION = "skeleton.contract-bundle.v1"
BUNDLE_VERSION = "1"


@dataclass(frozen=True, slots=True)
class ValidatedDocument:
    schema_id: str
    value: JSONValue
    source_sha256: str
    canonical_bytes: bytes
    canonical_sha256: str


def _contained_path(root: Path, relative_path: str) -> Path:
    if (
        not relative_path
        or "\\" in relative_path
        or relative_path.startswith("/")
        or ":" in relative_path
    ):
        raise ValueError(f"non-canonical bundle path: {relative_path!r}")
    resolved_root = root.resolve(strict=True)
    candidate = (resolved_root / relative_path).resolve(strict=True)
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError(f"bundle path escapes contracts root: {relative_path!r}")
    return candidate


def _as_mapping(value: JSONValue, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


class SchemaRegistry:
    """Load a complete authenticated schema bundle with no network resolver."""

    def __init__(self, contracts_root: Path | str) -> None:
        self.contracts_root = Path(contracts_root).resolve(strict=True)
        manifest_path = self.contracts_root / "bundle-manifest.json"
        manifest = _as_mapping(
            parse_raw_json(manifest_path.read_bytes()),
            "contract bundle",
        )
        if manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION:
            raise ValueError("unknown contract bundle schema version")
        if manifest.get("bundle_version") != BUNDLE_VERSION:
            raise ValueError("unknown contract bundle version")

        entries = manifest.get("schemas")
        if not isinstance(entries, list) or not entries:
            raise ValueError("contract bundle must contain schemas")
        paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
        schema_ids = [
            entry.get("schema_id") for entry in entries if isinstance(entry, dict)
        ]
        if len(paths) != len(entries) or paths != sorted(paths):
            raise ValueError("bundle schema paths must be complete and sorted")
        if len(paths) != len(set(paths)):
            raise ValueError("bundle schema paths must be unique")
        if len(schema_ids) != len(entries) or len(schema_ids) != len(set(schema_ids)):
            raise ValueError("bundle schema IDs must be complete and unique")

        schemas: dict[str, Mapping[str, Any]] = {}
        resources: list[tuple[str, Resource[Any]]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("bundle schema entry must be an object")
            schema_id = entry["schema_id"]
            schema_path = _contained_path(self.contracts_root, entry["path"])
            raw = schema_path.read_bytes()
            observed_sha256 = sha256_hex(raw)
            if observed_sha256 != entry["sha256"]:
                raise ValueError(
                    f"schema sha256 mismatch for {entry['path']}: "
                    f"expected {entry['sha256']}, observed {observed_sha256}"
                )
            schema = _as_mapping(parse_raw_json(raw), entry["path"])
            if schema.get("$schema") != SCHEMA_DRAFT or schema.get("$id") != schema_id:
                raise ValueError(f"schema identity mismatch for {entry['path']}")
            Draft202012Validator.check_schema(schema)
            schemas[schema_id] = schema
            resources.append((schema_id, Resource.from_contents(schema)))

        self._manifest = MappingProxyType(dict(manifest))
        self._schemas = MappingProxyType(schemas)
        self._resource_registry: Registry[Any] = Registry().with_resources(resources)
        self._validators = MappingProxyType(
            {
                schema_id: Draft202012Validator(
                    schema,
                    registry=self._resource_registry,
                )
                for schema_id, schema in schemas.items()
            }
        )
        fixture_entries = manifest.get("fixtures")
        if not isinstance(fixture_entries, list) or not fixture_entries:
            raise ValueError("contract bundle must contain fixtures")
        fixture_paths = [
            entry.get("path") for entry in fixture_entries if isinstance(entry, dict)
        ]
        if (
            len(fixture_paths) != len(fixture_entries)
            or fixture_paths != sorted(fixture_paths)
            or len(fixture_paths) != len(set(fixture_paths))
        ):
            raise ValueError("bundle fixture paths must be complete, sorted, and unique")
        verified_fixtures: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for entry in fixture_entries:
            if not isinstance(entry, dict):
                raise ValueError("bundle fixture entry must be an object")
            fixture_path = _contained_path(self.contracts_root, entry["path"])
            raw = fixture_path.read_bytes()
            if sha256_hex(raw) != entry["sha256"]:
                raise ValueError(f"fixture sha256 mismatch for {entry['path']}")
            records: list[Mapping[str, Any]] = []
            for line_number, line in enumerate(raw.splitlines(), start=1):
                value = parse_raw_json(line)
                if not isinstance(value, dict):
                    raise ValueError(
                        f"fixture {entry['path']}:{line_number} must be an object"
                    )
                records.append(MappingProxyType(value))
            if len(records) != entry["record_count"]:
                raise ValueError(f"fixture record count mismatch for {entry['path']}")
            verified_fixtures[entry["path"]] = tuple(records)
        self._fixtures = MappingProxyType(verified_fixtures)

    @property
    def manifest(self) -> Mapping[str, Any]:
        return self._manifest

    @property
    def schema_ids(self) -> tuple[str, ...]:
        return tuple(self._schemas)

    @property
    def fixture_paths(self) -> tuple[str, ...]:
        return tuple(self._fixtures)

    def fixture_records(self, path: str) -> tuple[Mapping[str, Any], ...]:
        try:
            return self._fixtures[path]
        except KeyError as error:
            raise KeyError(f"unknown fixture path: {path}") from error

    def fixture(self, fixture_id: str) -> Mapping[str, Any]:
        matches = [
            record
            for records in self._fixtures.values()
            for record in records
            if record.get("id") == fixture_id
        ]
        if len(matches) != 1:
            raise KeyError(f"fixture ID must resolve exactly once: {fixture_id}")
        return matches[0]

    def validate_raw(self, raw: bytes, expected_schema_id: str) -> ValidatedDocument:
        validator = self._validators.get(expected_schema_id)
        if validator is None:
            raise KeyError(f"unknown schema ID: {expected_schema_id}")
        source_sha256 = sha256_hex(raw)
        value = parse_raw_json(raw)
        validator.validate(value)
        canonical_bytes = canonicalize(value)
        return ValidatedDocument(
            schema_id=expected_schema_id,
            value=value,
            source_sha256=source_sha256,
            canonical_bytes=canonical_bytes,
            canonical_sha256=sha256_hex(canonical_bytes),
        )
