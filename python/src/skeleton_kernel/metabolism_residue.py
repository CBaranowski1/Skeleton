"""Privacy-sharded residue sketches for Phase 12 memory metabolism (MEM-17).

The residue field is a fixed-geometry family of integer count-min sketches:
one sketch per closed statistic family (``encounter``, ``co_occurrence``,
``retrieval_regret``, ``novelty``, ``failure``), each spread over four
privacy shards of depth 2 x width 16 bounded saturating counters.  Sketch
keys derive ONLY from closed category tuples -- four closed enum dimensions
(``memory_kind``, ``scope_class``, ``outcome_class``, ``regret_class``) --
via length-framed domain-separated SHA-256 under the per-shard domains
``SKELETON_PHASE12_RESIDUE_SHARD_{k}_V1``.  No free text, no memory
identifier, no digest of evicted content, and no float can enter key
material: ``assert_non_reconstructable`` structurally rejects any candidate
material carrying a 64-hex digest, an identifier-shaped string, or a string
outside the closed category vocabulary, and every tuple additionally passes
the Phase 10 ``scan_memory_document`` safety gate before any counter update.

Everything here is deterministic and integer-exact: no wall clock, no
floats, no hash randomization, and fixed iteration order (families in enum
order, shards ascending, rows in depth order), so identical multisets of
events produce byte-identical canonical snapshot documents.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Any

from .canonical import canonicalize, sha256_hex
from .memory_safety import MemorySafetyRejection, scan_memory_document
from .memory_types import ProvenanceClass
from .metabolism_store import ResidueSnapshotAppend, metabolism_record_identity
from .metabolism_types import (
    DispositionKind,
    EncounterDisposition,
    MemoryCapsule,
    RegretClass,
    ResidueStatisticFamily,
    SAFE_INTEGER_MAX,
    compute_phase12_identity,
)


# --------------------------------------------------------------------------
# Frozen versioned geometry: changing any constant orphans every prior
# residue snapshot, so all five are sealed under the geometry identity.
# --------------------------------------------------------------------------

RESIDUE_GEOMETRY_ID = "skeleton.memory-residue.v1"
RESIDUE_SCHEMA_VERSION = "skeleton.memory-residue.v1"
RESIDUE_GEOMETRY_VERSION = "skeleton.memory-residue-geometry.v1"
RESIDUE_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-residue.schema.json"

RESIDUE_SHARD_COUNT = 4
RESIDUE_DEPTH = 2
RESIDUE_WIDTH = 16
# Bounded saturating counters: exactly 2**32 - 1, strictly below the
# agent_types/metabolism_types SAFE_INTEGER_MAX bound.
RESIDUE_COUNTER_BOUND = 4_294_967_295
assert RESIDUE_COUNTER_BOUND < SAFE_INTEGER_MAX

SKELETON_PHASE12_RESIDUE_SNAPSHOT_V1 = "SKELETON_PHASE12_RESIDUE_SNAPSHOT_V1"
RESIDUE_SHARD_KEY_DOMAINS = tuple(
    f"SKELETON_PHASE12_RESIDUE_SHARD_{shard}_V1" for shard in range(RESIDUE_SHARD_COUNT)
)
RESIDUE_KEY_DERIVATION = "domain_framed_category_tuple_hash"
RESIDUE_CATEGORY_TUPLE_FIELDS = (
    "memory_kind",
    "scope_class",
    "outcome_class",
    "regret_class",
)

# Fixed family order: the canonical statistic-family order of the schema.
RESIDUE_FAMILIES = tuple(ResidueStatisticFamily)


class ResidueScopeClass(StrEnum):
    """Closed privacy-scope classes mirroring the capsule scope kinds."""

    NONE = "none"
    DOMAIN = "domain"
    MARKET = "market"


class ResidueOutcomeClass(StrEnum):
    """Closed outcome classes derived from optional-text presence only."""

    SURPRISING = "surprising"
    UNSURPRISING = "unsurprising"
    OUTCOME_ABSENT = "outcome_absent"


class ResidueRegretClass(StrEnum):
    """The four closed regret classes plus the explicit ``none`` branch."""

    NONE = "none"
    MISSED_RELEVANT = "missed_relevant"
    INCLUDED_IRRELEVANT = "included_irrelevant"
    BUDGET_STARVED = "budget_starved"
    LENS_ABSENT = "lens_absent"


assert {member.value for member in RegretClass} < {
    member.value for member in ResidueRegretClass
}

# The four closed dimension types, in schema category-tuple order.
RESIDUE_DIMENSION_TYPES: tuple[tuple[str, type[StrEnum]], ...] = (
    ("memory_kind", ProvenanceClass),
    ("scope_class", ResidueScopeClass),
    ("outcome_class", ResidueOutcomeClass),
    ("regret_class", ResidueRegretClass),
)

# The complete closed vocabulary admissible in residue key material: closed
# enum values and the four closed field names.  Nothing else may appear.
_CLOSED_KEY_NAMES = frozenset(
    {*RESIDUE_CATEGORY_TUPLE_FIELDS, "category_tuple", "category_tuple_pair"}
)
_CLOSED_VALUES = frozenset(
    member.value
    for _name, enum_type in RESIDUE_DIMENSION_TYPES
    for member in enum_type
)
_HEX_DIGITS = frozenset("0123456789abcdef")


class ResidueRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise ResidueRejection(code)


def _is_hex(value: str) -> bool:
    return bool(value) and all(character in _HEX_DIGITS for character in value)


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and _is_hex(value)


def assert_non_reconstructable(material: object) -> None:
    """Structurally prove candidate key material carries nothing invertible.

    Walks any mapping/sequence graph and rejects typed on the first member
    that is (a) a 64-hex content digest, (b) an identifier-shaped string
    (long hex, or a name ending in ``_id``/``_ids``/``_sha256`` outside the
    closed key vocabulary), or (c) any string outside the closed category
    vocabulary.  Non-string scalars (ints, floats, bools, ``None``) are
    rejected outright: residue key material is closed strings all the way
    down, so no invertible encoding can hide in a number.
    """

    stack: list[object] = [material]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > 4096:
            _reject("residue_key_material_bounds_exceeded")
        if isinstance(current, Mapping):
            for key in sorted(current):
                if not isinstance(key, str) or key not in _CLOSED_KEY_NAMES:
                    _reject("residue_key_material_not_closed")
                stack.append(current[key])
            continue
        if isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            stack.extend(current)
            continue
        if not isinstance(current, str):
            _reject("residue_key_material_not_closed")
        if _is_sha256(current):
            _reject("residue_key_material_digest_forbidden")
        lowered = current.casefold()
        if (len(lowered) >= 32 and _is_hex(lowered)) or lowered.endswith(
            ("_id", "_ids", "_sha256")
        ):
            _reject("residue_key_material_identifier_forbidden")
        if current not in _CLOSED_VALUES:
            _reject("residue_key_material_not_closed")


def _framed_digest(domain: str, payload: bytes) -> bytes:
    domain_bytes = domain.encode("ascii", errors="strict")
    return sha256(
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    ).digest()


def _scan_material(material: Mapping[str, Any]) -> None:
    """Run the structural proof then the Phase 10 safety scan, fail-closed."""

    assert_non_reconstructable(material)
    payload = canonicalize(material)
    source_event_id = _framed_digest(RESIDUE_SHARD_KEY_DOMAINS[0], payload).hex()
    try:
        scan_memory_document(
            material, schema_id=RESIDUE_SCHEMA_ID, source_event_id=source_event_id
        )
    except MemorySafetyRejection as error:
        raise ResidueRejection("residue_safety_scan_rejected") from error


@dataclass(frozen=True, slots=True)
class ResidueCategoryTuple:
    """One closed category tuple: exactly four closed enum dimensions.

    Constructing a tuple from a free string, identifier, digest, float, or
    any value that is not an exact member of the declared closed enum type
    is a typed rejection before any state exists.
    """

    memory_kind: ProvenanceClass
    scope_class: ResidueScopeClass
    outcome_class: ResidueOutcomeClass
    regret_class: ResidueRegretClass

    def __post_init__(self) -> None:
        for name, enum_type in RESIDUE_DIMENSION_TYPES:
            observed = getattr(self, name)
            if type(observed) is not enum_type:
                _reject("residue_category_dimension_not_closed")
        assert_non_reconstructable(self.as_mapping())

    def as_mapping(self) -> dict[str, str]:
        return {
            name: str(getattr(self, name).value)
            for name, _enum_type in RESIDUE_DIMENSION_TYPES
        }


@dataclass(frozen=True, slots=True)
class ResidueUpdate:
    """Typed receipt for one deterministic counter fold."""

    family: ResidueStatisticFamily
    shard_index: int
    positions: tuple[tuple[int, int], ...]
    saturated: bool


@dataclass(frozen=True, slots=True)
class ResidueEvictionContribution:
    """Category-level receipt for one committed statistical_residue eviction.

    Cites the committed disposition row identity only; no capsule identity,
    text, or digest of evicted content appears anywhere in the contribution.
    """

    disposition_id: str
    category: ResidueCategoryTuple
    updates: tuple[ResidueUpdate, ...]


def shard_of_family(family: ResidueStatisticFamily) -> int:
    """The closed shard-selection function: fixed family order modulo shards."""

    if type(family) is not ResidueStatisticFamily:
        _reject("residue_family_unknown")
    return RESIDUE_FAMILIES.index(family) % RESIDUE_SHARD_COUNT


def _category_tuple(value: object) -> ResidueCategoryTuple:
    if type(value) is not ResidueCategoryTuple:
        _reject("residue_category_tuple_required")
    return value


def _amount(value: object) -> int:
    if type(value) is not int or not 1 <= value <= RESIDUE_COUNTER_BOUND:
        _reject("residue_amount_invalid")
    return value


class ResidueSketch:
    """The fixed-geometry privacy-sharded integer sketch family.

    State is five family sketches, each four shards of depth 2 x width 16
    saturating counters.  All record functions take only closed-enum
    category tuples; updates iterate rows in fixed depth order and families
    in enum order, so state is insertion-order independent by construction.
    """

    __slots__ = ("_counters", "_update_count")

    def __init__(
        self,
        *,
        shard_count: int = RESIDUE_SHARD_COUNT,
        depth: int = RESIDUE_DEPTH,
        width: int = RESIDUE_WIDTH,
        counter_bound: int = RESIDUE_COUNTER_BOUND,
    ) -> None:
        declared = (shard_count, depth, width, counter_bound)
        frozen = (
            RESIDUE_SHARD_COUNT,
            RESIDUE_DEPTH,
            RESIDUE_WIDTH,
            RESIDUE_COUNTER_BOUND,
        )
        if any(type(item) is not int for item in declared) or declared != frozen:
            _reject("residue_geometry_invalid")
        self._counters: dict[ResidueStatisticFamily, list[list[list[int]]]] = {
            family: [
                [[0] * RESIDUE_WIDTH for _row in range(RESIDUE_DEPTH)]
                for _shard in range(RESIDUE_SHARD_COUNT)
            ]
            for family in RESIDUE_FAMILIES
        }
        self._update_count = 0

    # -- key derivation ----------------------------------------------------

    @staticmethod
    def _column(
        family: ResidueStatisticFamily,
        shard_index: int,
        row: int,
        material: Mapping[str, Any],
    ) -> int:
        payload = canonicalize(
            {
                "family": family.value,
                "geometry_version": RESIDUE_GEOMETRY_VERSION,
                "material": material,
                "row": row,
            }
        )
        digest = _framed_digest(RESIDUE_SHARD_KEY_DOMAINS[shard_index], payload)
        return int.from_bytes(digest[:8], "big") % RESIDUE_WIDTH

    def _fold(
        self,
        family: ResidueStatisticFamily,
        material: Mapping[str, Any],
        amount: int,
    ) -> ResidueUpdate:
        _scan_material(material)
        shard_index = shard_of_family(family)
        shard = self._counters[family][shard_index]
        positions: list[tuple[int, int]] = []
        saturated = False
        for row in range(RESIDUE_DEPTH):
            column = self._column(family, shard_index, row, material)
            current = shard[row][column]
            proposed = current + amount
            if proposed > RESIDUE_COUNTER_BOUND:
                proposed = RESIDUE_COUNTER_BOUND
                saturated = True
            shard[row][column] = proposed
            positions.append((row, column))
        self._update_count = min(SAFE_INTEGER_MAX, self._update_count + 1)
        return ResidueUpdate(family, shard_index, tuple(positions), saturated)

    # -- typed record functions: closed-enum arguments only ----------------

    def record_encounter(
        self, category: ResidueCategoryTuple, *, amount: int = 1
    ) -> ResidueUpdate:
        return self._fold(
            ResidueStatisticFamily.ENCOUNTER,
            {"category_tuple": _category_tuple(category).as_mapping()},
            _amount(amount),
        )

    def record_co_occurrence(
        self,
        first: ResidueCategoryTuple,
        second: ResidueCategoryTuple,
        *,
        amount: int = 1,
    ) -> ResidueUpdate:
        pair = sorted(
            (
                _category_tuple(first).as_mapping(),
                _category_tuple(second).as_mapping(),
            ),
            key=canonicalize,
        )
        return self._fold(
            ResidueStatisticFamily.CO_OCCURRENCE,
            {"category_tuple_pair": pair},
            _amount(amount),
        )

    def record_retrieval_regret(
        self, category: ResidueCategoryTuple, *, amount: int = 1
    ) -> ResidueUpdate:
        category = _category_tuple(category)
        if category.regret_class is ResidueRegretClass.NONE:
            _reject("residue_regret_class_missing")
        return self._fold(
            ResidueStatisticFamily.RETRIEVAL_REGRET,
            {"category_tuple": category.as_mapping()},
            _amount(amount),
        )

    def record_novelty(
        self, category: ResidueCategoryTuple, *, amount: int = 1
    ) -> ResidueUpdate:
        return self._fold(
            ResidueStatisticFamily.NOVELTY,
            {"category_tuple": _category_tuple(category).as_mapping()},
            _amount(amount),
        )

    def record_failure(
        self, category: ResidueCategoryTuple, *, amount: int = 1
    ) -> ResidueUpdate:
        return self._fold(
            ResidueStatisticFamily.FAILURE,
            {"category_tuple": _category_tuple(category).as_mapping()},
            _amount(amount),
        )

    # -- eviction contribution --------------------------------------------

    def record_eviction(
        self,
        capsule: MemoryCapsule,
        disposition: EncounterDisposition,
        *,
        regret_class: ResidueRegretClass = ResidueRegretClass.NONE,
    ) -> ResidueEvictionContribution:
        """Fold one committed statistical_residue eviction into the sketches.

        Extracts ONLY closed categorical features from the capsule view
        (provenance class, scope class, optional-text presence) and cites
        the committed disposition row identity.  Two evicted capsules with
        identical closed features produce identical contributions, so no
        individual content is recoverable from residue.
        """

        if not isinstance(capsule, MemoryCapsule):
            _reject("residue_capsule_required")
        if not isinstance(disposition, EncounterDisposition):
            _reject("residue_disposition_required")
        if disposition.disposition is not DispositionKind.STATISTICAL_RESIDUE:
            _reject("residue_disposition_not_statistical_residue")
        if not _is_sha256(disposition.residue_snapshot_id):
            _reject("residue_disposition_reference_missing")
        category = eviction_category_tuple(capsule, regret_class=regret_class)
        updates = [self.record_encounter(category)]
        updates.append(self.record_co_occurrence(category, category))
        if category.regret_class is not ResidueRegretClass.NONE:
            updates.append(self.record_retrieval_regret(category))
        updates.append(self.record_novelty(category))
        if category.outcome_class is ResidueOutcomeClass.OUTCOME_ABSENT:
            updates.append(self.record_failure(category))
        return ResidueEvictionContribution(
            disposition_id=disposition.disposition_id,
            category=category,
            updates=tuple(updates),
        )

    # -- state views -------------------------------------------------------

    @property
    def update_count(self) -> int:
        return self._update_count

    def counter(
        self, family: ResidueStatisticFamily, shard_index: int, row: int, column: int
    ) -> int:
        if type(family) is not ResidueStatisticFamily:
            _reject("residue_family_unknown")
        return int(self._counters[family][shard_index][row][column])

    def families_value(self) -> list[dict[str, Any]]:
        """The canonical schema-shaped ``families`` member, fixed order."""

        return [
            {
                "family": family.value,
                "shards": [
                    {
                        "key_domain": RESIDUE_SHARD_KEY_DOMAINS[shard_index],
                        "rows": [
                            list(self._counters[family][shard_index][row])
                            for row in range(RESIDUE_DEPTH)
                        ],
                        "shard_index": shard_index,
                    }
                    for shard_index in range(RESIDUE_SHARD_COUNT)
                ],
            }
            for family in RESIDUE_FAMILIES
        ]

    def state_root(self) -> str:
        return sha256_hex(canonicalize(self.families_value()))


def merge_sketches(first: ResidueSketch, second: ResidueSketch) -> ResidueSketch:
    """Element-wise saturating merge: deterministic, commutative, associative.

    Every merged counter is ``min(bound, a + b)``; because saturation is a
    final clamp over an associative-commutative integer sum, merge order can
    never change any counter value.
    """

    if not isinstance(first, ResidueSketch) or not isinstance(second, ResidueSketch):
        _reject("residue_sketch_required")
    merged = ResidueSketch()
    for family in RESIDUE_FAMILIES:
        for shard_index in range(RESIDUE_SHARD_COUNT):
            for row in range(RESIDUE_DEPTH):
                for column in range(RESIDUE_WIDTH):
                    total = (
                        first._counters[family][shard_index][row][column]
                        + second._counters[family][shard_index][row][column]
                    )
                    merged._counters[family][shard_index][row][column] = min(
                        RESIDUE_COUNTER_BOUND, total
                    )
    merged._update_count = min(
        SAFE_INTEGER_MAX, first._update_count + second._update_count
    )
    return merged


# --------------------------------------------------------------------------
# Eviction feature extraction: closed categorical features only.
# --------------------------------------------------------------------------


def eviction_category_tuple(
    capsule: MemoryCapsule,
    *,
    regret_class: ResidueRegretClass = ResidueRegretClass.NONE,
) -> ResidueCategoryTuple:
    """Extract ONLY closed categorical features from an evicted capsule view.

    Provenance class and scope class come from closed capsule enums; the
    outcome class comes from optional-text *presence* alone (the surprise
    presence boolean and outcome presence boolean), never from the text.
    """

    if not isinstance(capsule, MemoryCapsule):
        _reject("residue_capsule_required")
    if type(regret_class) is not ResidueRegretClass:
        _reject("residue_category_dimension_not_closed")
    try:
        scope_class = ResidueScopeClass(str(capsule.privacy_scope["scope_kind"]))
    except (KeyError, TypeError, ValueError) as error:
        raise ResidueRejection("residue_category_dimension_not_closed") from error
    surprise_present = capsule.surprise is not None
    outcome_present = capsule.outcome is not None
    if surprise_present:
        outcome_class = ResidueOutcomeClass.SURPRISING
    elif outcome_present:
        outcome_class = ResidueOutcomeClass.UNSURPRISING
    else:
        outcome_class = ResidueOutcomeClass.OUTCOME_ABSENT
    return ResidueCategoryTuple(
        memory_kind=capsule.provenance_class,
        scope_class=scope_class,
        outcome_class=outcome_class,
        regret_class=regret_class,
    )


# --------------------------------------------------------------------------
# Canonical content-addressed residue snapshot documents.
# --------------------------------------------------------------------------


def compute_residue_snapshot_identity(value: Mapping[str, Any]) -> str:
    return compute_phase12_identity(
        SKELETON_PHASE12_RESIDUE_SNAPSHOT_V1, "residue_snapshot_id", value
    )


def _snapshot_sha256(value: object, code: str) -> str:
    if not _is_sha256(value):
        _reject(code)
    return str(value)


def build_residue_snapshot(
    sketch: ResidueSketch,
    *,
    cycle_ordinal: int,
    cycle_input_root: str,
    fence_id: str,
    generation: int,
    attempt_ordinal: int,
) -> bytes:
    """Serialize complete sketch state as one canonical JCS snapshot document.

    The document is content-addressed under the schema's declared identity
    domain and carries the frozen geometry and key-derivation declaration,
    so byte-identity of two snapshots proves identical cycle inputs.
    """

    if not isinstance(sketch, ResidueSketch):
        _reject("residue_sketch_required")
    if type(cycle_ordinal) is not int or cycle_ordinal < 0:
        _reject("residue_snapshot_ordinal_invalid")
    if type(generation) is not int or generation < 0:
        _reject("residue_snapshot_generation_invalid")
    if type(attempt_ordinal) is not int or attempt_ordinal < 1:
        _reject("residue_snapshot_attempt_invalid")
    value: dict[str, Any] = {
        "schema_version": RESIDUE_SCHEMA_VERSION,
        "record_type": "residue_snapshot",
        "residue_snapshot_id": "0" * 64,
        "cycle_ordinal": cycle_ordinal,
        "cycle_input_root": _snapshot_sha256(
            cycle_input_root, "residue_snapshot_reference_invalid"
        ),
        "fence_id": _snapshot_sha256(fence_id, "residue_snapshot_reference_invalid"),
        "generation": generation,
        "attempt_ordinal": attempt_ordinal,
        "geometry": {
            "geometry_version": RESIDUE_GEOMETRY_VERSION,
            "shard_count": RESIDUE_SHARD_COUNT,
            "depth": RESIDUE_DEPTH,
            "width": RESIDUE_WIDTH,
        },
        "key_derivation": {
            "derivation": RESIDUE_KEY_DERIVATION,
            "category_tuple": list(RESIDUE_CATEGORY_TUPLE_FIELDS),
        },
        "families": sketch.families_value(),
    }
    value["residue_snapshot_id"] = compute_residue_snapshot_identity(value)
    return canonicalize(value)


def residue_snapshot_append(
    snapshot_bytes: bytes,
    *,
    cycle_ordinal: int,
    item_count: int,
    fence_id: str,
    generation: int,
    attempt_ordinal: int,
    recorded_at: str,
    statistic_family: ResidueStatisticFamily = ResidueStatisticFamily.ENCOUNTER,
) -> ResidueSnapshotAppend:
    """Build the typed sole-writer append for one complete snapshot document.

    The row identity is the store's domain-framed identity of the exact
    canonical bytes, so the append round-trips byte-verified through the
    ``MetabolismStore`` replay surface.  The complete five-family snapshot
    is ledgered under the canonical first statistic family label.
    """

    if type(statistic_family) is not ResidueStatisticFamily:
        _reject("residue_family_unknown")
    if type(item_count) is not int or item_count < 0:
        _reject("residue_snapshot_item_count_invalid")
    return ResidueSnapshotAppend(
        metabolism_record_identity("residue_snapshot", snapshot_bytes),
        statistic_family.value,
        cycle_ordinal,
        item_count,
        fence_id,
        generation,
        attempt_ordinal,
        recorded_at,
        bytes(snapshot_bytes),
    )


__all__ = [
    "RESIDUE_CATEGORY_TUPLE_FIELDS",
    "RESIDUE_COUNTER_BOUND",
    "RESIDUE_DEPTH",
    "RESIDUE_DIMENSION_TYPES",
    "RESIDUE_FAMILIES",
    "RESIDUE_GEOMETRY_ID",
    "RESIDUE_GEOMETRY_VERSION",
    "RESIDUE_KEY_DERIVATION",
    "RESIDUE_SCHEMA_ID",
    "RESIDUE_SCHEMA_VERSION",
    "RESIDUE_SHARD_COUNT",
    "RESIDUE_SHARD_KEY_DOMAINS",
    "RESIDUE_WIDTH",
    "ResidueCategoryTuple",
    "ResidueEvictionContribution",
    "ResidueOutcomeClass",
    "ResidueRegretClass",
    "ResidueRejection",
    "ResidueScopeClass",
    "ResidueSketch",
    "ResidueUpdate",
    "SKELETON_PHASE12_RESIDUE_SNAPSHOT_V1",
    "assert_non_reconstructable",
    "build_residue_snapshot",
    "compute_residue_snapshot_identity",
    "eviction_category_tuple",
    "merge_sketches",
    "residue_snapshot_append",
    "shard_of_family",
]
