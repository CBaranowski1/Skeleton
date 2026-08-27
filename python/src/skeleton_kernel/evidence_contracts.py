"""Immutable Phase 7 models over the authenticated contract publication."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, TypeAlias

from .canonical import canonicalize, sha256_hex
from .models import SchemaId
from .schema_registry import SchemaRegistry, ValidatedDocument


class ContractVerdict(StrEnum):
    """Closed fixture disposition vocabulary."""

    ACCEPT = "accept"
    REJECT = "reject"


class FixtureRejectionCode(StrEnum):
    """Closed Phase 7 fixture rejection vocabulary."""

    ALIAS_PRIMARY_FORBIDDEN = "alias_primary_forbidden"
    AUTHORIZATION_MISSING = "authorization_missing"
    BOUNDARY_UNKNOWN = "boundary_unknown"
    DECISION_AMBIGUOUS = "decision_ambiguous"
    EXTERNAL_TRANSMISSION_NOT_AUTHORIZED = "external_transmission_not_authorized"
    FUTURE_VISIBILITY = "future_visibility"
    GENESIS_IMMUTABLE = "genesis_immutable"
    LEGAL_TERMS_INCOMPLETE = "legal_terms_incomplete"
    LINEAGE_CYCLE = "lineage_cycle"
    MUTATION_SURFACE_FORBIDDEN = "mutation_surface_forbidden"
    PREVIEW_AUTHORITY_FORBIDDEN = "preview_authority_forbidden"
    PROTECTED_CONTENT_FORBIDDEN = "protected_content_forbidden"
    REBUILD_DIVERGENCE = "rebuild_divergence"
    REFERENCE_STATE_MISSING = "reference_state_missing"
    RIGHTS_EXPIRED = "rights_expired"
    SOURCE_COMMIT_INVALID = "source_commit_invalid"
    TIMESTAMP_INVALID = "timestamp_invalid"
    UNIVERSE_ACTION_UNKNOWN = "universe_action_unknown"


PHASE07_SCHEMA_HASHES: Mapping[str, str] = MappingProxyType(
    {
        "https://schemas.skeleton.local/v1/canonical-event.schema.json": "7eb90eb52b54653ee627f014932749a040891f691db40c460777cb22e7569a38",
        "https://schemas.skeleton.local/v1/deletion-execution.schema.json": "faf0dc47b1037c350197ee0f1357308644fb32a8220ad4c4ba293ffe3c8eadfe",
        "https://schemas.skeleton.local/v1/deletion-preview.schema.json": "b875c224b6922de2b6e8febcc11795a83d9cbaa5e895e4401fa5edeea7361d5f",
        "https://schemas.skeleton.local/v1/evidence-health.schema.json": "91d401bcce11823d276103eb8a2ab365962073cdaab01bf5e8f7275c93749d1c",
        "https://schemas.skeleton.local/v1/evidence-manifest.schema.json": "885fb0eef85a337bd4a7b339c0d0a0f524b05982feb3dffad4b8e93cc9ff12d8",
        "https://schemas.skeleton.local/v1/identity-fact.schema.json": "f7024bbad9afcf18c56dcdae7c9b2737c559800b26c454b17a8551a24bda54cb",
        "https://schemas.skeleton.local/v1/kernel-status-v2.schema.json": "3a7b8056b61a5cf81f1dcafa33063d4d3120a1fff83b3e5b4e2a1613c6525211",
        "https://schemas.skeleton.local/v1/legal-terms-record.schema.json": "6e276b2a52f2bb92564afd3720206012eefb61997684c78f1fbcc7df04bbcfa4",
        "https://schemas.skeleton.local/v1/lineage-record.schema.json": "b185fe72e7c7e3490417fef7a8a47a4514946971c75cf5eeb2ad0e027782ffc0",
        "https://schemas.skeleton.local/v1/reference-fact.schema.json": "0b977546e97fcc10f96a2ae1b291dd6fa1c74ce77ec23ee8a652ce6caca31593",
        "https://schemas.skeleton.local/v1/rights-record.schema.json": "85cc01a179593ec2535c1fd518372970fface4cbf8426abd4a0b0678091464c0",
        "https://schemas.skeleton.local/v1/rights-use-decision.schema.json": "ed690690baee04cbe260a55fe669b4d127e8e8b7305703513c91fa4a6819ecb7",
        "https://schemas.skeleton.local/v1/rights-use-request.schema.json": "e14b0c26e4a8c08422de5e94617014cf42f11c90a750aa46abbda595a82815fe",
        "https://schemas.skeleton.local/v1/stable-identity.schema.json": "6d6fa08ae60b4d23d439062832095e1aff2854a1a035596aaaeb6a7d71994930",
        "https://schemas.skeleton.local/v1/universe-event.schema.json": "ef5b9fa451c4bd0a113d38f815c5b06f8cbf257e19aa19713cc95893005505a4",
    }
)

RAW_FIXTURE_IDENTITIES: Mapping[str, tuple[str, int, int]] = MappingProxyType(
    {
        "fixtures/phase07-fixtures.jsonl": (
            "6f4818682996e477bb4826f9ca52530d1562e5f748b900893916f5c88c13e162",
            17086,
            15,
        ),
        "fixtures/phase07-poison-fixtures.jsonl": (
            "a57674d319c5166f7fbacf317315b445af314d8e84a3243f3587b603966dcaa3",
            10750,
            19,
        ),
    }
)


class ContractRejection(ValueError):
    """Stable redacted rejection with no submitted payload or path."""

    def __init__(
        self,
        code: str,
        *,
        subject_id: str | None = None,
        schema_id: str | None = None,
    ) -> None:
        self.code = code
        self.subject_id = subject_id
        self.schema_id = schema_id
        super().__init__(code)


FrozenScalar: TypeAlias = None | bool | int | float | str
FrozenValue: TypeAlias = FrozenScalar | tuple["FrozenValue", ...] | "FrozenObject"


class FrozenObject(Mapping[str, FrozenValue]):
    """Recursively immutable JSON object preserving canonical insertion order."""

    __slots__ = ("_values",)

    def __init__(self, values: Mapping[str, FrozenValue]) -> None:
        self._values = MappingProxyType(dict(values))

    def __getitem__(self, key: str) -> FrozenValue:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


def _freeze(value: Any) -> FrozenValue:
    if isinstance(value, Mapping):
        return FrozenObject({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, bool | int | float | str):
        return value
    raise ContractRejection("mutable_or_unknown_value")


@dataclass(frozen=True, slots=True, init=False)
class ValidatedContract:
    """Closed immutable wrapper for one registry-validated Phase 7 document."""

    schema_id: str
    value: FrozenValue
    source_sha256: str
    canonical_bytes: bytes
    canonical_sha256: str

    def __init__(self, validated: ValidatedDocument, token: object) -> None:
        if token is not _VALIDATED_CONSTRUCTION or not isinstance(
            validated, ValidatedDocument
        ):
            raise TypeError("ValidatedContract requires a ValidatedDocument")
        if validated.schema_id not in PHASE07_SCHEMA_HASHES:
            raise ContractRejection(
                "unknown_schema_id", schema_id=validated.schema_id
            )
        canonical_bytes = canonicalize(validated.value)
        if (
            canonical_bytes != validated.canonical_bytes
            or sha256_hex(canonical_bytes) != validated.canonical_sha256
        ):
            raise ContractRejection(
                "canonical_identity_mismatch", schema_id=validated.schema_id
            )
        if validated.source_sha256 != validated.canonical_sha256:
            raise ContractRejection(
                "source_not_canonical", schema_id=validated.schema_id
            )
        object.__setattr__(self, "schema_id", validated.schema_id)
        object.__setattr__(self, "value", _freeze(validated.value))
        object.__setattr__(self, "source_sha256", validated.source_sha256)
        object.__setattr__(self, "canonical_bytes", canonical_bytes)
        object.__setattr__(self, "canonical_sha256", validated.canonical_sha256)


_VALIDATED_CONSTRUCTION = object()


def _validated_contract(validated: ValidatedDocument) -> ValidatedContract:
    return ValidatedContract(validated, _VALIDATED_CONSTRUCTION)


@dataclass(frozen=True, slots=True)
class _FixtureSnapshot:
    schema_id: str
    verdict: ContractVerdict
    rejection_code: FixtureRejectionCode | None
    source_sha256: str
    canonical_bytes: bytes
    record_sha256: str


_CONTRACT_SET_CONSTRUCTION = object()


@dataclass(frozen=True, slots=True, init=False)
class Phase07ContractSet:
    """Exact authenticated Phase 7 publication and immutable fixture adapters."""

    schema_ids: frozenset[str]
    raw_fixture_identities: Mapping[str, tuple[str, int, int]]
    _fixtures: Mapping[str, _FixtureSnapshot]

    def __init__(
        self,
        schema_ids: frozenset[str],
        raw_fixture_identities: Mapping[str, tuple[str, int, int]],
        fixtures: Mapping[str, _FixtureSnapshot],
        token: object,
    ) -> None:
        if token is not _CONTRACT_SET_CONSTRUCTION:
            raise TypeError("Phase07ContractSet requires authenticated publication")
        object.__setattr__(self, "schema_ids", schema_ids)
        object.__setattr__(self, "raw_fixture_identities", raw_fixture_identities)
        object.__setattr__(self, "_fixtures", fixtures)

    @classmethod
    def from_authenticated_contracts(
        cls, authenticated: Mapping[str, object]
    ) -> Phase07ContractSet:
        if set(authenticated) != {"manifest", "index", "phase07"}:
            raise ContractRejection("authenticated_contract_shape")
        manifest = authenticated["manifest"]
        index = authenticated["index"]
        phase07 = authenticated["phase07"]
        if not isinstance(manifest, Mapping) or not isinstance(index, Mapping):
            raise ContractRejection("authenticated_contract_shape")
        if not isinstance(phase07, Mapping) or set(phase07) != set(
            RAW_FIXTURE_IDENTITIES
        ):
            raise ContractRejection("authenticated_fixture_shape")

        schema_entries = manifest.get("schemas")
        fixture_entries = manifest.get("fixtures")
        sources = index.get("sources")
        if not all(isinstance(value, list) for value in (schema_entries, fixture_entries, sources)):
            raise ContractRejection("authenticated_contract_shape")
        observed_schemas = {
            str(entry.get("schema_id")): str(entry.get("sha256"))
            for entry in schema_entries
            if isinstance(entry, Mapping)
            and str(entry.get("schema_id")) in PHASE07_SCHEMA_HASHES
        }
        if observed_schemas != dict(PHASE07_SCHEMA_HASHES):
            raise ContractRejection("schema_identity_mismatch")

        manifest_fixtures = {
            str(entry.get("path")): (
                str(entry.get("sha256")),
                int(entry.get("record_count", -1)),
            )
            for entry in fixture_entries
            if isinstance(entry, Mapping)
            and str(entry.get("path")) in RAW_FIXTURE_IDENTITIES
        }
        source_map = {
            str(source.get("path")): source
            for source in sources
            if isinstance(source, Mapping)
            and str(source.get("path")) in RAW_FIXTURE_IDENTITIES
        }
        snapshots: dict[str, _FixtureSnapshot] = {}
        for path, (expected_sha, _bytes, expected_count) in RAW_FIXTURE_IDENTITIES.items():
            if manifest_fixtures.get(path) != (expected_sha, expected_count):
                raise ContractRejection("raw_fixture_identity_mismatch")
            source = source_map.get(path)
            records = phase07[path]
            if (
                not isinstance(source, Mapping)
                or source.get("sha256") != expected_sha
                or source.get("record_count") != expected_count
                or not isinstance(records, tuple)
                or len(records) != expected_count
            ):
                raise ContractRejection("raw_fixture_identity_mismatch")
            cases = source.get("cases")
            if not isinstance(cases, list) or len(cases) != expected_count:
                raise ContractRejection("fixture_case_inventory")
            case_map = {
                str(case.get("id")): case
                for case in cases
                if isinstance(case, Mapping)
            }
            if len(case_map) != expected_count:
                raise ContractRejection("fixture_case_inventory")
            for record in records:
                if not isinstance(record, Mapping):
                    raise ContractRejection("fixture_case_shape")
                fixture_id = str(record.get("id"))
                case = case_map.get(fixture_id)
                schema_id = str(record.get("schema_id"))
                payload = record.get("payload")
                if case is None or schema_id not in PHASE07_SCHEMA_HASHES:
                    raise ContractRejection("fixture_case_identity")
                canonical_bytes = canonicalize(payload)
                source_sha256 = sha256_hex(canonical_bytes)
                if (
                    source_sha256 != record.get("source_sha256")
                    or case.get("source_sha256") != source_sha256
                    or case.get("canonical_sha256") != source_sha256
                ):
                    raise ContractRejection("fixture_case_content_identity")
                for field in (
                    "schema_id",
                    "expected_schema_valid",
                    "expected_verdict",
                    "rejection_code",
                ):
                    if case.get(field) != record.get(field):
                        raise ContractRejection("fixture_case_metadata_identity")
                verdict = ContractVerdict(str(record.get("expected_verdict")))
                rejection = record.get("rejection_code")
                rejection_code = (
                    None
                    if rejection is None
                    else FixtureRejectionCode(str(rejection))
                )
                if (verdict is ContractVerdict.ACCEPT) is (rejection_code is not None):
                    raise ContractRejection("fixture_case_disposition")
                record_sha256 = sha256_hex(canonicalize(record))
                if fixture_id in snapshots:
                    raise ContractRejection("duplicate_fixture_id")
                snapshots[fixture_id] = _FixtureSnapshot(
                    schema_id=schema_id,
                    verdict=verdict,
                    rejection_code=rejection_code,
                    source_sha256=source_sha256,
                    canonical_bytes=canonical_bytes,
                    record_sha256=record_sha256,
                )
        if len(snapshots) != 34:
            raise ContractRejection("fixture_case_inventory")
        return cls(
            schema_ids=frozenset(PHASE07_SCHEMA_HASHES),
            raw_fixture_identities=RAW_FIXTURE_IDENTITIES,
            fixtures=MappingProxyType(snapshots),
            token=_CONTRACT_SET_CONSTRUCTION,
        )

    def wrap_validated(
        self, registry: SchemaRegistry, validated: ValidatedDocument
    ) -> ValidatedContract:
        """Revalidate exact canonical bytes through the authenticated registry."""

        if not isinstance(registry, SchemaRegistry):
            raise TypeError("registry must be SchemaRegistry")
        if not isinstance(validated, ValidatedDocument):
            raise TypeError("validated must be ValidatedDocument")
        revalidated = registry.validate_raw(
            validated.canonical_bytes, validated.schema_id
        )
        if (
            revalidated.canonical_sha256 != validated.canonical_sha256
            or revalidated.value != validated.value
        ):
            raise ContractRejection(
                "validated_document_mismatch", schema_id=validated.schema_id
            )
        return _validated_contract(validated)

    def wrap_fixture(self, record: Mapping[str, object]) -> ValidatedContract:
        """Wrap one exact record from the already authenticated frozen corpus."""

        fixture_id = str(record.get("id"))
        snapshot = self._fixtures.get(fixture_id)
        if snapshot is None or sha256_hex(canonicalize(record)) != snapshot.record_sha256:
            raise ContractRejection("fixture_identity_mismatch", subject_id=fixture_id)
        if snapshot.verdict is ContractVerdict.REJECT:
            assert snapshot.rejection_code is not None
            raise ContractRejection(
                snapshot.rejection_code.value,
                subject_id=fixture_id,
                schema_id=snapshot.schema_id,
            )
        validated = ValidatedDocument(
            schema_id=snapshot.schema_id,
            value=record["payload"],  # type: ignore[arg-type]
            source_sha256=snapshot.source_sha256,
            canonical_bytes=snapshot.canonical_bytes,
            canonical_sha256=snapshot.source_sha256,
        )
        return _validated_contract(validated)
