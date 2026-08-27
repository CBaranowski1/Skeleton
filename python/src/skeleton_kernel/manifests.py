"""Exact Phase 7 evidence manifests and deterministic rebuild diagnostics."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
import hashlib
from types import MappingProxyType
from typing import Any, Final

from .canonical import JSONValue, canonicalize, sha256_hex
from .evidence_contracts import PHASE07_SCHEMA_HASHES
from .object_store import ObjectStore, ObjectStoreRejection, StoredObject
from .schema_registry import SchemaRegistry


EVIDENCE_MANIFEST_SCHEMA: Final[str] = (
    "https://schemas.skeleton.local/v1/evidence-manifest.schema.json"
)
REBUILD_COMPARISON_ORDER: Final[tuple[str, ...]] = (
    "schema",
    "source_commit",
    "parser_build",
    "schema_bundle",
    "rights",
    "identity_reference",
    "raw_object",
    "partition",
    "correction",
    "exclusion",
    "output",
)
CANONICAL_ORDER: Final[dict[str, list[str]]] = {
    "objects": ["role", "content_sha256"],
    "partitions": ["partition_key", "content_sha256"],
    "schema_bindings": ["schema_id", "sha256"],
    "calendar_facts": ["calendar_id", "effective_from", "content_sha256"],
    "identities": [
        "kind",
        "stable_identity_id",
        "effective_from",
        "content_sha256",
    ],
    "universe_events": ["content_sha256"],
    "reference_facts": [
        "kind",
        "stable_identity_id",
        "effective_from",
        "content_sha256",
    ],
    "corrections": ["superseded_id", "correction_id"],
    "exclusions": ["reason_code", "subject_id"],
    "rights_bindings": ["rights_record_id", "rights_decision_id"],
    "outputs": ["role", "content_sha256"],
}
QUARANTINE_CLASSES: Final[frozenset[str]] = frozenset(
    {"legacy", "synthetic", "stale", "revoked_rights", "contaminated"}
)


class ManifestRejection(ValueError):
    """Stable manifest rejection with no payload or path echo."""

    def __init__(self, code: str, *, quarantine_count: int = 0) -> None:
        self.code = code
        self.quarantine_count = quarantine_count
        super().__init__(code)


class ReproducibilityFailure(ValueError):
    """The first exact rebuild divergence, represented only by safe digests."""

    def __init__(
        self,
        field: str,
        expected_sha256: str,
        observed_sha256: str,
    ) -> None:
        self.code = "rebuild_divergence"
        self.field = field
        self.expected_sha256 = expected_sha256
        self.observed_sha256 = observed_sha256
        super().__init__(
            f"{self.code}:{field}:{expected_sha256}:{observed_sha256}"
        )


def _digest(value: JSONValue) -> str:
    return sha256_hex(canonicalize(value))


def _record_payload_digest(record: Mapping[str, Any]) -> str:
    payload = record.get("payload")
    source_sha256 = record.get("source_sha256")
    if not isinstance(payload, dict) or not isinstance(source_sha256, str):
        raise ManifestRejection("authenticated_fixture_shape")
    observed = _digest(payload)
    if observed != source_sha256:
        raise ManifestRejection("authenticated_fixture_identity")
    return observed


def _component_values(value: Mapping[str, Any]) -> dict[str, JSONValue]:
    return {
        "schema": value["schema_version"],
        "source_commit": value["code"]["source_commit"],
        "parser_build": {
            "parser": value["code"]["parser"],
            "build": value["code"]["build"],
            "environment": value["code"]["environment"],
        },
        "schema_bundle": value["schema_bindings"],
        "rights": value["rights_bindings"],
        "identity_reference": {
            "calendar_facts": value["calendar_facts"],
            "identities": value["identities"],
            "universe_events": value["universe_events"],
            "reference_facts": value["reference_facts"],
        },
        "raw_object": value["objects"],
        "partition": value["partitions"],
        "correction": value["corrections"],
        "exclusion": value["exclusions"],
        "output": {
            "compression": value["compression"],
            "reconstruction": value["reconstruction"],
            "outputs": value["outputs"],
        },
    }


def _component_digests(value: Mapping[str, Any]) -> dict[str, str]:
    components = _component_values(value)
    return {name: _digest(components[name]) for name in REBUILD_COMPARISON_ORDER}


def _manifest_declaration_id(value: Mapping[str, Any]) -> str:
    declaration = {key: item for key, item in value.items() if key != "manifest_id"}
    return _digest(declaration)


def _hash_field(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ManifestRejection(code)
    return value


def _normalize_corrections(
    corrections: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for correction in corrections:
        if set(correction) != {"superseded_id", "correction_id"}:
            raise ManifestRejection("manifest_correction_shape")
        normalized.append(
            {
                "superseded_id": _hash_field(
                    correction["superseded_id"], "manifest_correction_identity"
                ),
                "correction_id": _hash_field(
                    correction["correction_id"], "manifest_correction_identity"
                ),
            }
        )
    normalized.sort(key=lambda item: (item["superseded_id"], item["correction_id"]))
    if len({(item["superseded_id"], item["correction_id"]) for item in normalized}) != len(normalized):
        raise ManifestRejection("manifest_correction_duplicate")
    return normalized


def _normalize_exclusions(
    exclusions: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    allowed = QUARANTINE_CLASSES | {"unresolved_identity", "unresolved_reference"}
    normalized: list[dict[str, str]] = []
    for exclusion in exclusions:
        if set(exclusion) != {"reason_code", "subject_id"}:
            raise ManifestRejection("manifest_exclusion_shape")
        reason = exclusion["reason_code"]
        if reason not in allowed:
            raise ManifestRejection("manifest_exclusion_reason")
        normalized.append(
            {
                "reason_code": reason,
                "subject_id": _hash_field(
                    exclusion["subject_id"], "manifest_exclusion_identity"
                ),
            }
        )
    normalized.sort(key=lambda item: (item["reason_code"], item["subject_id"]))
    if len({(item["reason_code"], item["subject_id"]) for item in normalized}) != len(normalized):
        raise ManifestRejection("manifest_exclusion_duplicate")
    return normalized


@dataclass(frozen=True, slots=True)
class ManifestSelection:
    """Closed inputs recomputed before a manifest may be paper-eligible."""

    quarantine_classes: tuple[str, ...]
    rights_current: bool
    identity_resolved: bool
    raw_authenticated: bool
    reconstruction_exact: bool

    def __post_init__(self) -> None:
        classes = tuple(sorted(set(self.quarantine_classes)))
        if any(item not in QUARANTINE_CLASSES for item in classes):
            raise ManifestRejection("quarantine_unknown")
        for value in (
            self.rights_current,
            self.identity_resolved,
            self.raw_authenticated,
            self.reconstruction_exact,
        ):
            if type(value) is not bool:
                raise ManifestRejection("promotion_state_invalid")
        object.__setattr__(self, "quarantine_classes", classes)

    @property
    def quarantine_count(self) -> int:
        return len(self.quarantine_classes)


@dataclass(frozen=True, slots=True)
class ManifestArtifact:
    value: dict[str, Any]
    canonical_bytes: bytes
    manifest_id: str
    canonical_sha256: str
    manifest_content_sha256: str
    component_digests: Mapping[str, str]
    raw_content_sha256s: tuple[str, ...]
    output_content_sha256s: tuple[str, ...]
    _registry: SchemaRegistry = field(repr=False, compare=False)
    _observed_overrides: Mapping[str, str] = field(
        default_factory=dict, repr=False, compare=False
    )

    def with_mutation(self, field: str, observed_sha256: str) -> ManifestArtifact:
        return self.with_mutations({field: observed_sha256})

    def with_mutations(
        self, mutations: Mapping[str, str]
    ) -> ManifestArtifact:
        overrides = dict(self._observed_overrides)
        for name, digest in mutations.items():
            if name not in REBUILD_COMPARISON_ORDER:
                raise ManifestRejection("rebuild_field_unknown")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ManifestRejection("rebuild_digest_invalid")
            overrides[name] = digest
        return replace(self, _observed_overrides=MappingProxyType(overrides))


class ManifestBuilder:
    """Build complete manifests only from authenticated fixture identities."""

    __slots__ = ("_records", "_store", "_registry")

    def __init__(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        store: ObjectStore | None = None,
        registry: SchemaRegistry | None = None,
    ) -> None:
        if not isinstance(store, ObjectStore | None):
            raise TypeError("store must be ObjectStore or None")
        if not isinstance(registry, SchemaRegistry | None):
            raise TypeError("registry must be SchemaRegistry or None")
        identifiers = [str(record.get("id")) for record in records]
        if identifiers != sorted(identifiers) or len(identifiers) != len(
            set(identifiers)
        ):
            raise ManifestRejection("authenticated_fixture_order")
        verified: dict[str, Mapping[str, Any]] = {}
        for record in records:
            identifier = str(record.get("id"))
            _record_payload_digest(record)
            verified[identifier] = record
        for required in (
            "evidence-manifest-valid",
            "reference-fact-valid",
            "rights-record-valid",
            "rights-use-decision-valid",
            "stable-identity-valid",
            "universe-event-valid",
        ):
            if required not in verified:
                raise ManifestRejection("authenticated_fixture_incomplete")
        self._records = MappingProxyType(verified)
        self._store = store
        self._registry = registry

    @property
    def object_store(self) -> ObjectStore | None:
        """Return the injected content store for composition identity checks."""

        return self._store

    @classmethod
    def from_fixture_records(
        cls,
        records: Sequence[Mapping[str, Any]],
        *,
        store: ObjectStore | None = None,
        registry: SchemaRegistry | None = None,
    ) -> ManifestBuilder:
        return cls(records, store=store, registry=registry)

    def _require_registry(self) -> SchemaRegistry:
        if self._registry is None:
            raise ManifestRejection("manifest_schema_registry_required")
        manifest_entries = [
            entry
            for entry in self._registry.manifest["schemas"]
            if entry["schema_id"] == EVIDENCE_MANIFEST_SCHEMA
        ]
        if (
            len(manifest_entries) != 1
            or manifest_entries[0]["sha256"]
            != PHASE07_SCHEMA_HASHES[EVIDENCE_MANIFEST_SCHEMA]
        ):
            raise ManifestRejection("manifest_schema_identity")
        return self._registry

    def _publish_object(self, raw: bytes) -> StoredObject:
        digest = hashlib.sha256(raw).hexdigest()
        if self._store is None:
            return StoredObject(
                digest,
                len(raw),
                ObjectStore.relative_path_for(digest),
            )
        return self._store.put_verified(raw)

    def build(
        self,
        *,
        objects: Sequence[str | bytes],
        corrections: Sequence[Mapping[str, str]] = (),
        exclusions: Sequence[Mapping[str, str]] = (),
    ) -> ManifestArtifact:
        registry = self._require_registry()
        if not objects:
            raise ManifestRejection("manifest_objects_empty")
        raw_values = tuple(
            value.encode("utf-8") if isinstance(value, str) else value
            for value in objects
        )
        if not all(isinstance(value, bytes) for value in raw_values):
            raise TypeError("manifest objects must be str or bytes")
        stored_by_hash = {
            stored.content_sha256: stored
            for stored in (self._publish_object(value) for value in raw_values)
        }
        stored_objects = tuple(
            stored_by_hash[digest] for digest in sorted(stored_by_hash)
        )
        normalized_corrections = _normalize_corrections(corrections)
        normalized_exclusions = _normalize_exclusions(exclusions)
        object_bindings = sorted(
            (
                {
                    "role": "raw",
                    "content_sha256": stored.content_sha256,
                    "byte_length": stored.byte_length,
                    "media_type": "application/octet-stream",
                }
                for stored in stored_objects
            ),
            key=lambda item: (item["role"], item["content_sha256"]),
        )
        partitions = sorted(
            (
                {
                    "partition_key": f"fixture-{ordinal:06d}",
                    "content_sha256": stored.content_sha256,
                    "ordinal": ordinal,
                }
                for ordinal, stored in enumerate(stored_objects)
            ),
            key=lambda item: (item["partition_key"], item["content_sha256"]),
        )
        schema_bindings = sorted(
            (
                {"schema_id": entry["schema_id"], "sha256": entry["sha256"]}
                for entry in registry.manifest["schemas"]
            ),
            key=lambda item: (item["schema_id"], item["sha256"]),
        )
        fixture = self._records["evidence-manifest-valid"]["payload"]
        if not isinstance(fixture, Mapping):
            raise ManifestRejection("authenticated_fixture_shape")
        legacy_code = fixture.get("code")
        if not isinstance(legacy_code, Mapping):
            raise ManifestRejection("authenticated_fixture_shape")
        source_commit = legacy_code.get("source_commit")
        parser_sha256 = legacy_code.get("parser_code_sha256")
        build_id = legacy_code.get("build_id")
        if not all(isinstance(value, str) for value in (source_commit, parser_sha256, build_id)):
            raise ManifestRejection("authenticated_fixture_shape")

        identity_sha256 = _record_payload_digest(
            self._records["stable-identity-valid"]
        )
        reference_sha256 = _record_payload_digest(
            self._records["reference-fact-valid"]
        )
        universe_sha256 = _record_payload_digest(
            self._records["universe-event-valid"]
        )
        rights_record_sha256 = _record_payload_digest(
            self._records["rights-record-valid"]
        )
        rights_decision_sha256 = _record_payload_digest(
            self._records["rights-use-decision-valid"]
        )
        schema_bundle_sha256 = _digest(schema_bindings)
        dataset_bytes = canonicalize(object_bindings)
        dataset_object = self._publish_object(dataset_bytes)
        outputs = [
            {
                "role": "dataset",
                "content_sha256": dataset_object.content_sha256,
                "byte_length": len(dataset_bytes),
                "media_type": "application/json",
            }
        ]
        recipe_inputs: dict[str, JSONValue] = {
            "objects": object_bindings,
            "partitions": partitions,
            "schema_bindings": schema_bindings,
            "identity": identity_sha256,
            "reference": reference_sha256,
            "universe": universe_sha256,
            "rights_record": rights_record_sha256,
            "rights_decision": rights_decision_sha256,
            "corrections": normalized_corrections,
            "exclusions": normalized_exclusions,
            "source_commit": source_commit,
            "parser": parser_sha256,
            "build": build_id,
            "outputs": outputs,
        }
        value: dict[str, Any] = {
            "schema_version": "skeleton.evidence-manifest.v1",
            "manifest_id": "0" * 64,
            "objects": object_bindings,
            "partitions": partitions,
            "schema_bindings": schema_bindings,
            "calendar_facts": [
                {
                    "calendar_id": "phase07-fixture-calendar",
                    "effective_from": "2026-08-01T00:00:00Z",
                    "content_sha256": reference_sha256,
                }
            ],
            "identities": [
                {
                    "kind": "stable_identity",
                    "stable_identity_id": identity_sha256,
                    "effective_from": "2026-08-01T00:00:00Z",
                    "content_sha256": identity_sha256,
                }
            ],
            "universe_events": [universe_sha256],
            "reference_facts": [
                {
                    "kind": "currency",
                    "stable_identity_id": identity_sha256,
                    "effective_from": "2026-08-01T00:00:00Z",
                    "content_sha256": reference_sha256,
                }
            ],
            "corrections": normalized_corrections,
            "exclusions": normalized_exclusions,
            "rights_bindings": [
                {
                    "rights_record_id": rights_record_sha256,
                    "rights_decision_id": rights_decision_sha256,
                }
            ],
            "code": {
                "source_commit": source_commit,
                "parser": {
                    "version": "phase07-fixture-parser",
                    "code_sha256": parser_sha256,
                },
                "build": {
                    "build_id": build_id,
                    "toolchain_sha256": _digest(
                        {"build_id": build_id, "source_commit": source_commit}
                    ),
                },
                "environment": {
                    "profile_id": "phase07-authenticated-fixture",
                    "profile_sha256": schema_bundle_sha256,
                },
            },
            "compression": {
                "codec": "content_addressed_deduplication",
                "parameters_sha256": None,
            },
            "reconstruction": {
                "algorithm_version": "phase07-exact-rebuild-v1",
                "recipe_sha256": _digest(recipe_inputs),
                "preserves_raw_identity": True,
                "preserves_rights_lineage": True,
                "preserves_correction_history": True,
            },
            "outputs": outputs,
            "canonical_order": CANONICAL_ORDER,
        }
        value["manifest_id"] = _manifest_declaration_id(value)
        raw = canonicalize(value)
        try:
            validated = registry.validate_raw(raw, EVIDENCE_MANIFEST_SCHEMA)
        except Exception as error:
            raise ManifestRejection("manifest_schema_invalid") from error
        if validated.canonical_bytes != raw or validated.value != value:
            raise ManifestRejection("manifest_canonical_identity")
        manifest_object = self._publish_object(raw)
        return ManifestArtifact(
            value=value,
            canonical_bytes=raw,
            manifest_id=str(value["manifest_id"]),
            canonical_sha256=validated.canonical_sha256,
            manifest_content_sha256=manifest_object.content_sha256,
            component_digests=MappingProxyType(_component_digests(value)),
            raw_content_sha256s=tuple(
                item["content_sha256"] for item in object_bindings
            ),
            output_content_sha256s=tuple(
                item["content_sha256"] for item in outputs
            ),
            _registry=registry,
        )

    def build_fixture(self, fixture_id: str) -> ManifestArtifact:
        record = self._records.get(fixture_id)
        if record is None or fixture_id != "evidence-manifest-valid":
            raise ManifestRejection("authenticated_fixture_not_found")
        raw = canonicalize(record["payload"])
        if sha256_hex(raw) != record["source_sha256"]:
            raise ManifestRejection("authenticated_fixture_identity")
        return self.build(objects=(raw,))

    def build_for_promotion(self, selection: ManifestSelection) -> ManifestArtifact:
        if not isinstance(selection, ManifestSelection):
            raise TypeError("selection must be ManifestSelection")
        if selection.quarantine_classes:
            raise ManifestRejection(
                f"quarantine_{selection.quarantine_classes[0]}",
                quarantine_count=selection.quarantine_count,
            )
        if not selection.rights_current:
            raise ManifestRejection("promotion_rights_not_current")
        if not selection.identity_resolved:
            raise ManifestRejection("promotion_identity_unresolved")
        if not selection.raw_authenticated:
            raise ManifestRejection("promotion_raw_unauthenticated")
        if not selection.reconstruction_exact:
            raise ManifestRejection("promotion_reconstruction_unverified")
        return self.build_fixture("evidence-manifest-valid")


class ManifestRebuilder:
    """Reconstruct an exact manifest or stop at the first frozen divergence."""

    __slots__ = ("_store",)

    def __init__(
        self,
        *,
        store: ObjectStore | None = None,
        root: Any | None = None,
    ) -> None:
        if store is not None and root is not None:
            raise TypeError("provide store or root, not both")
        if store is None:
            if root is None:
                raise TypeError("store or root is required")
            store = ObjectStore(root)
        if not isinstance(store, ObjectStore):
            raise TypeError("store must be ObjectStore")
        self._store = store

    @property
    def object_store(self) -> ObjectStore:
        """Return the exact injected store used for rebuild verification."""

        return self._store

    def rebuild(self, manifest: ManifestArtifact) -> ManifestArtifact:
        if not isinstance(manifest, ManifestArtifact):
            raise TypeError("manifest must be ManifestArtifact")
        for field_name in REBUILD_COMPARISON_ORDER:
            expected = manifest.component_digests[field_name]
            observed = manifest._observed_overrides.get(field_name, expected)
            if observed != expected:
                raise ReproducibilityFailure(field_name, expected, observed)
        for content_sha256 in manifest.raw_content_sha256s:
            try:
                self._store.get_verified(content_sha256)
            except ObjectStoreRejection as error:
                observed = hashlib.sha256(error.code.encode("ascii")).hexdigest()
                raise ReproducibilityFailure(
                    "raw_object", manifest.component_digests["raw_object"], observed
                ) from None
        try:
            manifest_bytes = self._store.get_verified(
                manifest.manifest_content_sha256
            )
        except ObjectStoreRejection as error:
            observed = hashlib.sha256(error.code.encode("ascii")).hexdigest()
            raise ReproducibilityFailure(
                "output", manifest.canonical_sha256, observed
            ) from None
        if manifest_bytes != manifest.canonical_bytes:
            raise ReproducibilityFailure(
                "output",
                manifest.canonical_sha256,
                hashlib.sha256(manifest_bytes).hexdigest(),
            )
        expected_output = canonicalize(manifest.value["objects"])
        for content_sha256 in manifest.output_content_sha256s:
            try:
                observed_output = self._store.get_verified(content_sha256)
            except ObjectStoreRejection as error:
                observed = hashlib.sha256(error.code.encode("ascii")).hexdigest()
                raise ReproducibilityFailure(
                    "output", manifest.component_digests["output"], observed
                ) from None
            if observed_output != expected_output:
                raise ReproducibilityFailure(
                    "output",
                    hashlib.sha256(expected_output).hexdigest(),
                    hashlib.sha256(observed_output).hexdigest(),
                )
        validated = manifest._registry.validate_raw(
            manifest.canonical_bytes, EVIDENCE_MANIFEST_SCHEMA
        )
        if (
            validated.canonical_bytes != manifest.canonical_bytes
            or validated.canonical_sha256 != manifest.canonical_sha256
            or _manifest_declaration_id(manifest.value) != manifest.manifest_id
            or _component_digests(manifest.value) != dict(manifest.component_digests)
        ):
            observed = hashlib.sha256(validated.canonical_bytes).hexdigest()
            raise ReproducibilityFailure(
                "output", manifest.canonical_sha256, observed
            )
        return replace(manifest, _observed_overrides=MappingProxyType({}))


__all__ = [
    "ManifestArtifact",
    "ManifestBuilder",
    "ManifestSelection",
    "ManifestRebuilder",
    "ManifestRejection",
    "ObjectStore",
    "ReproducibilityFailure",
]
