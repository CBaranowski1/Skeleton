"""Deterministic Phase 12 metabolism stage implementations (Plans 12-09/12-10).

Four pure stage executors over one immutable input snapshot:

``run_deduplicate_stage``
    Lossless exact-identity deduplication: groups snapshot items whose
    capsule ``canonical_sha256`` values are byte-equal (re-verified against
    the snapshot bytes before anything is recorded), collapses each group to
    one survivor, and emits one content-addressed ``duplicate_edge`` record
    per absorbed member plus a byte-exact reconstruction proof per group.
    Nothing byte-distinct is ever merged and no similarity metric exists.

``run_delta_encode_stage``
    Bounded delta encoding: near-duplicate capsules (same privacy scope and
    provenance class) are chained in sorted content-identity order through
    exact byte-level edit scripts.  Every patch is proven invertible to the
    byte inside the stage before it is recorded; chains are bounded by
    ``DELTA_CHAIN_MAX_DEPTH`` with a proven rebase to full bytes, patches
    larger than their targets yield full retention, and no chain ever
    crosses a privacy scope.

``run_cluster_stage``
    Deterministic prototype-plus-exception clustering over a closed integer
    feature vocabulary with exact ``Fraction`` distances, iterated in sorted
    content-identity order.  Every member with nonzero prototype distance or
    a counterevidence mark (a present ``surprise``) is an explicit exception.

``run_crystallize_stage``
    Causal/procedural crystallization: clusters meeting the frozen minimum
    support compile into content-addressed ``compressed_concept`` or
    ``compressed_procedure`` candidate documents carrying the complete
    sorted source and exception identity sets, exact integer tallies and
    fraction-string ratios, and a bounded safety scan before emission.

Replacement authority belongs exclusively to the Plan 12-12 gates.  The
published compression-lineage schema permits ``gate_receipt_id: "none"``
only on a genesis edge (empty ``parent_ids``); every parent-bearing edge
requires a sealed gate receipt.  Stages therefore never append replacement
lineage rows: they emit ``PendingLineageProposal`` values flagged
``pending`` whose digests are folded into the committed stage receipt, and
``finalize_lineage_document`` binds a proposal to a gate receipt into exact
schema-valid lineage bytes once the gates exist.

Every stage is a pure function of its ``StageInputState``: no wall clock,
no randomness, no floats, no unsorted iteration.  Store writes flow only
through ``commit_stage_outcome`` over the narrow ``StageStore`` append
protocol; nothing here mutates, deletes, tombstones, or disposes any
existing row.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from fractions import Fraction
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Protocol

from .canonical import canonicalize, sha256_hex
from .memory_safety import MemorySafetyRejection, scan_memory_document
from .memory_types import ProvenanceClass
from .metabolism_store import (
    OperationReceipt,
    StageReceiptAppend,
    metabolism_record_identity,
)
from .metabolism_types import (
    CLOSED_PRIVACY_SCOPE_KINDS,
    GENESIS_SHA256,
    LINEAGE_SCHEMA_VERSION,
    MemoryCapsule,
    NONE_SENTINEL,
    SAFE_INTEGER_MAX,
    StageKind,
    compute_lineage_identity,
    compute_phase12_identity,
)


# ---------------------------------------------------------------------------
# Frozen stage constants
# ---------------------------------------------------------------------------

DELTA_CHAIN_MAX_DEPTH = 8
MAX_DELTA_OPERATIONS = 64
DELTA_MIN_COPY_LENGTH = 16
CLUSTER_PROFILE_ID = "skeleton.memory-cluster.v1"
CRYSTALLIZE_MIN_SUPPORT = 3

STAGE_RECEIPT_SCHEMA_VERSION = "skeleton.metabolism-stage-receipt.v1"
STAGE_ARTIFACT_SCHEMA_VERSION = "skeleton.metabolism-stage-artifact.v1"
DELTA_PATCH_SCHEMA_VERSION = "skeleton.metabolism-delta-patch.v1"
LINEAGE_PROPOSAL_SCHEMA_VERSION = "skeleton.metabolism-lineage-proposal.v1"

SKELETON_PHASE12_STAGE_RECEIPT_V1 = "SKELETON_PHASE12_STAGE_RECEIPT_V1"
SKELETON_PHASE12_STAGE_ARTIFACT_V1 = "SKELETON_PHASE12_STAGE_ARTIFACT_V1"
SKELETON_PHASE12_STAGE_ITEMS_V1 = "SKELETON_PHASE12_STAGE_ITEMS_V1"
SKELETON_PHASE12_LINEAGE_PROPOSAL_V1 = "SKELETON_PHASE12_LINEAGE_PROPOSAL_V1"
SKELETON_PHASE12_FEATURE_BUCKET_V1 = "SKELETON_PHASE12_FEATURE_BUCKET_V1"

# The bounded safety scan requires a schema-id-shaped context string; stage
# artifacts are internal candidates, not one of the ten published schemas.
STAGE_ARTIFACT_SCHEMA_ID = (
    "https://schemas.skeleton.local/v1/metabolism-stage-artifact.schema.json"
)

PENDING_STATUS = "pending"

# The four stage kinds implemented by this module, in frozen pipeline order.
METABOLISM_STAGE_ORDER = (
    StageKind.LOSSLESS_DEDUPLICATION,
    StageKind.SEMANTIC_DELTA_ENCODING,
    StageKind.PROTOTYPE_EXCEPTION_CLUSTERING,
    StageKind.CRYSTALLIZATION,
)
_STAGE_ORDINALS = MappingProxyType(
    {
        StageKind.LOSSLESS_DEDUPLICATION: 0,
        StageKind.SEMANTIC_DELTA_ENCODING: 1,
        StageKind.PROTOTYPE_EXCEPTION_CLUSTERING: 2,
        StageKind.CRYSTALLIZATION: 3,
    }
)

CLOSED_STAGE_ARTIFACT_KINDS = (
    "cluster_record",
    "compressed_concept",
    "compressed_procedure",
    "crystallization_deferral",
    "delta_artifact",
    "duplicate_edge",
    "full_retention",
    "rebase_artifact",
    "reconstruction_failure",
    "reconstruction_proof",
)

CLOSED_STAGE_REJECTION_CODES = (
    "crystallize_unknown_member",
    "delta_chain_depth_exceeded",
    "delta_patch_invalid",
    "delta_scope_boundary_violation",
    "lineage_proposal_invalid",
    "reconstruction_failed",
    "stage_artifact_identity_mismatch",
    "stage_input_duplicate_capsule",
    "stage_input_duplicate_encounter",
    "stage_input_invalid",
    "stage_prior_receipt_invalid",
    "stage_snapshot_digest_mismatch",
)

# Closed integer feature vocabulary (Plan 12-10): every component is an int,
# every enum mapping frozen here.  Weights and threshold are exact Fractions.
_SCOPE_KIND_ORDINALS = MappingProxyType(
    {kind: ordinal for ordinal, kind in enumerate(CLOSED_PRIVACY_SCOPE_KINDS)}
)
_PROVENANCE_ORDINALS = MappingProxyType(
    {member: ordinal for ordinal, member in enumerate(ProvenanceClass)}
)
SCOPE_BUCKET_MODULUS = 64
ACTION_BUCKET_MODULUS = 128
CLUSTER_FEATURE_NAMES = (
    "scope_kind_ordinal",
    "scope_bucket",
    "provenance_ordinal",
    "prediction_present",
    "outcome_present",
    "surprise_present",
    "alternatives_count",
    "changed_beliefs_count",
    "action_bucket",
)
CLUSTER_FEATURE_WEIGHTS = (
    Fraction(8),
    Fraction(1),
    Fraction(4),
    Fraction(2),
    Fraction(2),
    Fraction(1),
    Fraction(1, 2),
    Fraction(1, 2),
    Fraction(1, 128),
)
CLUSTER_DISTANCE_THRESHOLD = Fraction(3)


class MetabolismStageRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise MetabolismStageRejection(code)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    frame = (
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return sha256(frame).hexdigest()


def _digest_bucket(payload: bytes, modulus: int) -> int:
    return int(_framed_digest(SKELETON_PHASE12_FEATURE_BUCKET_V1, payload)[:16], 16) % modulus


# ---------------------------------------------------------------------------
# Typed stage values
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SnapshotItem:
    """One resident snapshot row: an encounter identity bound to its capsule."""

    encounter_id: str
    capsule: MemoryCapsule


@dataclass(frozen=True, slots=True)
class StageArtifact:
    """One content-addressed, gate-pending stage artifact document."""

    artifact_kind: str
    artifact_id: str
    canonical_bytes: bytes
    value: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class PendingLineageProposal:
    """A parent-bearing lineage PROPOSAL flagged pending until the 12-12 gates.

    The compression-lineage schema forbids a parent-bearing edge without a
    sealed gate receipt, so stages never append these as lineage rows; the
    proposal digest is folded into the committed stage receipt instead.
    """

    proposal_id: str
    child_id: str
    parent_ids: tuple[str, ...]
    producing_stage: StageKind
    status: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class StageInputState:
    """Immutable input snapshot plus cycle binding for one stage run."""

    items: tuple[SnapshotItem, ...]
    cycle_ordinal: int
    cycle_input_root: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    prior_receipt_id: str = GENESIS_SHA256
    delta_depths: Mapping[str, int] = field(default_factory=dict)
    artifacts: tuple[StageArtifact, ...] = ()


@dataclass(frozen=True, slots=True)
class StageOutcome:
    """The complete deterministic result of one stage run."""

    stage: StageKind
    stage_ordinal: int
    items_in: tuple[SnapshotItem, ...]
    items_out: tuple[SnapshotItem, ...]
    artifacts: tuple[StageArtifact, ...]
    proposals: tuple[PendingLineageProposal, ...]
    input_root: str
    output_root: str
    receipt_value: Mapping[str, Any]
    receipt_bytes: bytes
    receipt_id: str
    receipt_row_id: str


class StageExecutor(Protocol):
    """The executor protocol the 12-08 cycle engine can adopt."""

    def __call__(self, state: StageInputState) -> StageOutcome: ...


class StageStore(Protocol):
    """The narrow append-only store handle stages commit receipts through."""

    def append_stage_receipt(
        self, item: StageReceiptAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt: ...


# ---------------------------------------------------------------------------
# Input validation (fail-closed, typed)
# ---------------------------------------------------------------------------


def _bounded_int(value: object, minimum: int, code: str) -> int:
    if type(value) is not int or not minimum <= value <= SAFE_INTEGER_MAX:
        _reject(code)
    return int(value)


def _validate_state(state: StageInputState, stage: StageKind) -> None:
    if not isinstance(state, StageInputState) or not isinstance(state.items, tuple):
        _reject("stage_input_invalid")
    _bounded_int(state.cycle_ordinal, 0, "stage_input_invalid")
    _bounded_int(state.generation, 0, "stage_input_invalid")
    _bounded_int(state.attempt_ordinal, 1, "stage_input_invalid")
    for identity in (state.cycle_input_root, state.fence_id):
        if not _is_sha256(identity):
            _reject("stage_input_invalid")
    ordinal = _STAGE_ORDINALS[stage]
    if ordinal == 0:
        if state.prior_receipt_id != GENESIS_SHA256:
            _reject("stage_prior_receipt_invalid")
    elif not _is_sha256(state.prior_receipt_id) or state.prior_receipt_id == GENESIS_SHA256:
        _reject("stage_prior_receipt_invalid")
    if not isinstance(state.delta_depths, Mapping):
        _reject("stage_input_invalid")
    for capsule_id, depth in state.delta_depths.items():
        if not _is_sha256(capsule_id):
            _reject("stage_input_invalid")
        if type(depth) is not int or not 0 <= depth <= DELTA_CHAIN_MAX_DEPTH:
            _reject("stage_input_invalid")
    encounter_ids: set[str] = set()
    capsule_ids: set[str] = set()
    for item in state.items:
        if not isinstance(item, SnapshotItem) or not isinstance(item.capsule, MemoryCapsule):
            _reject("stage_input_invalid")
        if not _is_sha256(item.encounter_id):
            _reject("stage_input_invalid")
        if item.encounter_id in encounter_ids:
            _reject("stage_input_duplicate_encounter")
        encounter_ids.add(item.encounter_id)
        # Re-verify every declared digest against the snapshot bytes before
        # any grouping decision: a corrupted snapshot rejects typed.
        if sha256_hex(item.capsule.canonical_bytes) != item.capsule.canonical_sha256:
            _reject("stage_snapshot_digest_mismatch")
        if stage is not StageKind.LOSSLESS_DEDUPLICATION:
            if item.capsule.capsule_id in capsule_ids:
                _reject("stage_input_duplicate_capsule")
            capsule_ids.add(item.capsule.capsule_id)


def _sorted_items(items: tuple[SnapshotItem, ...]) -> tuple[SnapshotItem, ...]:
    return tuple(
        sorted(items, key=lambda item: (item.capsule.capsule_id, item.encounter_id))
    )


# ---------------------------------------------------------------------------
# Content addressing for receipts, artifacts, proposals, and roots
# ---------------------------------------------------------------------------


def _artifact(kind: str, body: Mapping[str, Any]) -> StageArtifact:
    if kind not in CLOSED_STAGE_ARTIFACT_KINDS:
        _reject("stage_input_invalid")
    value: dict[str, Any] = {
        "schema_version": STAGE_ARTIFACT_SCHEMA_VERSION,
        "record_type": kind,
        **{str(key): item for key, item in body.items()},
    }
    artifact_id = compute_phase12_identity(
        SKELETON_PHASE12_STAGE_ARTIFACT_V1, "artifact_id", value
    )
    value["artifact_id"] = artifact_id
    raw = canonicalize(value)
    return StageArtifact(
        artifact_kind=kind,
        artifact_id=artifact_id,
        canonical_bytes=raw,
        value=_freeze(value),
    )


def _proposal(
    child_id: str, parent_ids: Sequence[str], stage: StageKind
) -> PendingLineageProposal:
    parents = tuple(sorted(set(parent_ids)))
    if not parents or not all(_is_sha256(parent) for parent in parents):
        _reject("lineage_proposal_invalid")
    if not _is_sha256(child_id) or child_id in parents:
        _reject("lineage_proposal_invalid")
    value: dict[str, Any] = {
        "schema_version": LINEAGE_PROPOSAL_SCHEMA_VERSION,
        "record_type": "compression_lineage_proposal",
        "child_id": child_id,
        "parent_ids": list(parents),
        "producing_stage": stage.value,
        "status": PENDING_STATUS,
    }
    proposal_id = compute_phase12_identity(
        SKELETON_PHASE12_LINEAGE_PROPOSAL_V1, "proposal_id", value
    )
    value["proposal_id"] = proposal_id
    return PendingLineageProposal(
        proposal_id=proposal_id,
        child_id=child_id,
        parent_ids=parents,
        producing_stage=stage,
        status=PENDING_STATUS,
        canonical_bytes=canonicalize(value),
    )


def finalize_lineage_document(
    proposal: PendingLineageProposal, gate_receipt_id: str
) -> bytes:
    """Bind one pending proposal to a sealed 12-12 gate receipt.

    Returns exact JCS-canonical compression-lineage bytes that authenticate
    through ``lineage_from_raw``; the stages themselves never call this with
    a fabricated receipt because no gate surface exists before Plan 12-12.
    """

    if not isinstance(proposal, PendingLineageProposal) or proposal.status != PENDING_STATUS:
        _reject("lineage_proposal_invalid")
    if not _is_sha256(gate_receipt_id) or gate_receipt_id == GENESIS_SHA256:
        _reject("lineage_proposal_invalid")
    value: dict[str, Any] = {
        "schema_version": LINEAGE_SCHEMA_VERSION,
        "record_type": "compression_lineage",
        "child_id": proposal.child_id,
        "parent_ids": list(proposal.parent_ids),
        "producing_stage": proposal.producing_stage.value,
        "gate_receipt_id": gate_receipt_id,
    }
    value["lineage_id"] = compute_lineage_identity(value)
    return canonicalize(value)


def _items_root(items: tuple[SnapshotItem, ...]) -> str:
    material = sorted(
        [item.capsule.capsule_id, item.encounter_id] for item in items
    )
    return _framed_digest(SKELETON_PHASE12_STAGE_ITEMS_V1, canonicalize(material))


def _output_root(
    items: tuple[SnapshotItem, ...],
    artifacts: tuple[StageArtifact, ...],
    proposals: tuple[PendingLineageProposal, ...],
) -> str:
    material = {
        "artifact_ids": [artifact.artifact_id for artifact in artifacts],
        "item_ids": sorted(
            [item.capsule.capsule_id, item.encounter_id] for item in items
        ),
        "proposal_ids": [proposal.proposal_id for proposal in proposals],
    }
    return _framed_digest(SKELETON_PHASE12_STAGE_ITEMS_V1, canonicalize(material))


def _outcome(
    stage: StageKind,
    state: StageInputState,
    items_out: tuple[SnapshotItem, ...],
    artifacts: tuple[StageArtifact, ...],
    proposals: tuple[PendingLineageProposal, ...],
) -> StageOutcome:
    ordinal = _STAGE_ORDINALS[stage]
    input_root = _items_root(state.items)
    output_root = _output_root(items_out, artifacts, proposals)
    body: dict[str, Any] = {
        "schema_version": STAGE_RECEIPT_SCHEMA_VERSION,
        "record_type": "stage_receipt",
        "cycle_ordinal": state.cycle_ordinal,
        "cycle_input_root": state.cycle_input_root,
        "fence_id": state.fence_id,
        "generation": state.generation,
        "attempt_ordinal": state.attempt_ordinal,
        "stage": stage.value,
        "stage_ordinal": ordinal,
        "prior_receipt_id": state.prior_receipt_id,
        "input_root": input_root,
        "output_root": output_root,
        "input_item_count": len(state.items),
        "output_item_count": len(items_out),
    }
    receipt_id = compute_phase12_identity(
        SKELETON_PHASE12_STAGE_RECEIPT_V1, "stage_receipt_id", body
    )
    body["stage_receipt_id"] = receipt_id
    raw = canonicalize(body)
    return StageOutcome(
        stage=stage,
        stage_ordinal=ordinal,
        items_in=state.items,
        items_out=items_out,
        artifacts=artifacts,
        proposals=proposals,
        input_root=input_root,
        output_root=output_root,
        receipt_value=_freeze(body),
        receipt_bytes=raw,
        receipt_id=receipt_id,
        receipt_row_id=metabolism_record_identity("stage_receipt", raw),
    )


# ---------------------------------------------------------------------------
# Stage 0: lossless exact-identity deduplication
# ---------------------------------------------------------------------------


def run_deduplicate_stage(state: StageInputState) -> StageOutcome:
    """Collapse byte-identical capsules only; every duplicate is provably
    reconstructible from its survivor because their bytes are one identity."""

    _validate_state(state, StageKind.LOSSLESS_DEDUPLICATION)
    groups: dict[str, list[SnapshotItem]] = {}
    for item in _sorted_items(state.items):
        groups.setdefault(item.capsule.canonical_sha256, []).append(item)

    survivors: list[SnapshotItem] = []
    artifacts: list[StageArtifact] = []
    for digest in sorted(groups, key=lambda key: groups[key][0].capsule.capsule_id):
        members = sorted(groups[digest], key=lambda item: item.encounter_id)
        survivor = members[0]
        # Exact-equality proof: recompute the digest from the survivor bytes
        # and require byte-equality for every absorbed member.  Equality is
        # canonical_sha256 equality only; no similarity path exists.
        recomputed = sha256_hex(survivor.capsule.canonical_bytes)
        if recomputed != digest:
            _reject("stage_snapshot_digest_mismatch")
        duplicates = members[1:]
        for duplicate in duplicates:
            if duplicate.capsule.canonical_bytes != survivor.capsule.canonical_bytes:
                _reject("stage_snapshot_digest_mismatch")
            artifacts.append(
                _artifact(
                    "duplicate_edge",
                    {
                        "capsule_id": survivor.capsule.capsule_id,
                        "canonical_sha256": digest,
                        "duplicate_encounter_id": duplicate.encounter_id,
                        "status": PENDING_STATUS,
                        "survivor_encounter_id": survivor.encounter_id,
                    },
                )
            )
        if duplicates:
            artifacts.append(
                _artifact(
                    "reconstruction_proof",
                    {
                        "byte_length": len(survivor.capsule.canonical_bytes),
                        "capsule_id": survivor.capsule.capsule_id,
                        "duplicate_encounter_ids": [
                            item.encounter_id for item in duplicates
                        ],
                        "equal": True,
                        "recomputed_sha256": recomputed,
                        "stage": StageKind.LOSSLESS_DEDUPLICATION.value,
                        "survivor_encounter_id": survivor.encounter_id,
                        "target_sha256": digest,
                    },
                )
            )
        survivors.append(survivor)

    return _outcome(
        StageKind.LOSSLESS_DEDUPLICATION,
        state,
        _sorted_items(tuple(survivors)),
        tuple(artifacts),
        (),
    )


# ---------------------------------------------------------------------------
# Stage 1: bounded delta encoding with byte-exact reconstruction proofs
# ---------------------------------------------------------------------------


def encode_delta(base: MemoryCapsule, target: MemoryCapsule) -> dict[str, Any]:
    """Encode ``target`` against ``base`` as an exact byte-level edit script.

    Rejects typed when the pair crosses a privacy scope: delta chains never
    bridge scopes, in the stage or through this public surface.
    """

    if not isinstance(base, MemoryCapsule) or not isinstance(target, MemoryCapsule):
        _reject("stage_input_invalid")
    if canonicalize(dict(base.privacy_scope)) != canonicalize(dict(target.privacy_scope)):
        _reject("delta_scope_boundary_violation")
    base_bytes = base.canonical_bytes
    target_bytes = target.canonical_bytes
    # difflib block matching is a pure deterministic function of the two
    # byte sequences; autojunk stays off so no length heuristic applies.
    matcher = SequenceMatcher(None, base_bytes, target_bytes, autojunk=False)
    operations: list[dict[str, Any]] = []
    literal = bytearray()
    for tag, base_start, base_end, target_start, target_end in matcher.get_opcodes():
        if tag == "equal" and base_end - base_start >= DELTA_MIN_COPY_LENGTH:
            if literal:
                operations.append({"op": "insert", "bytes_hex": bytes(literal).hex()})
                literal = bytearray()
            operations.append(
                {"op": "copy", "offset": base_start, "length": base_end - base_start}
            )
        else:
            # Short matches and replacements fold into one literal insert so
            # the edit script stays compact and its op count bounded.
            literal.extend(target_bytes[target_start:target_end])
    if literal or not operations:
        operations.append({"op": "insert", "bytes_hex": bytes(literal).hex()})
    return {
        "schema_version": DELTA_PATCH_SCHEMA_VERSION,
        "operations": operations,
    }


def apply_delta(base_bytes: bytes, patch: Mapping[str, Any]) -> bytes:
    """Apply one exact copy/insert edit script; malformed shapes reject typed."""

    if not isinstance(base_bytes, bytes) or not isinstance(patch, Mapping):
        _reject("delta_patch_invalid")
    if set(patch) != {"schema_version", "operations"}:
        _reject("delta_patch_invalid")
    if patch["schema_version"] != DELTA_PATCH_SCHEMA_VERSION:
        _reject("delta_patch_invalid")
    operations = patch["operations"]
    if (
        not isinstance(operations, (list, tuple))
        or not operations
        or len(operations) > MAX_DELTA_OPERATIONS
    ):
        _reject("delta_patch_invalid")
    pieces: list[bytes] = []
    for operation in operations:
        if not isinstance(operation, Mapping):
            _reject("delta_patch_invalid")
        if set(operation) == {"op", "offset", "length"} and operation["op"] == "copy":
            offset = operation["offset"]
            length = operation["length"]
            if (
                type(offset) is not int
                or type(length) is not int
                or offset < 0
                or length < 1
                or offset + length > len(base_bytes)
            ):
                _reject("delta_patch_invalid")
            pieces.append(base_bytes[offset : offset + length])
            continue
        if set(operation) == {"op", "bytes_hex"} and operation["op"] == "insert":
            insert_hex = operation["bytes_hex"]
            if (
                not isinstance(insert_hex, str)
                or not insert_hex
                or len(insert_hex) % 2 != 0
                or any(character not in "0123456789abcdef" for character in insert_hex)
            ):
                _reject("delta_patch_invalid")
            pieces.append(bytes.fromhex(insert_hex))
            continue
        _reject("delta_patch_invalid")
    return b"".join(pieces)


def reconstruct_chain(
    base_bytes: bytes, patches: Sequence[Mapping[str, Any]]
) -> bytes:
    """Walk one delta chain from full bytes; over-depth walks reject typed."""

    if not isinstance(base_bytes, bytes) or not isinstance(patches, (list, tuple)):
        _reject("delta_patch_invalid")
    if len(patches) > DELTA_CHAIN_MAX_DEPTH:
        _reject("delta_chain_depth_exceeded")
    current = base_bytes
    for patch in patches:
        current = apply_delta(current, patch)
    return current


def verify_reconstruction(
    base_bytes: bytes, patch: Mapping[str, Any], expected_sha256: str
) -> dict[str, Any]:
    """Prove one patch reconstructs its target to the byte, or reject typed."""

    if not _is_sha256(expected_sha256):
        _reject("stage_input_invalid")
    reconstructed = apply_delta(base_bytes, patch)
    reconstructed_sha256 = sha256_hex(reconstructed)
    if reconstructed_sha256 != expected_sha256:
        _reject("reconstruction_failed")
    return {
        "base_sha256": sha256_hex(base_bytes),
        "byte_length": len(reconstructed),
        "equal": True,
        "patch_sha256": sha256_hex(canonicalize(dict(patch))),
        "reconstructed_sha256": reconstructed_sha256,
        "target_sha256": expected_sha256,
    }


def _delta_group_key(capsule: MemoryCapsule) -> tuple[str, str]:
    scope = canonicalize(dict(capsule.privacy_scope)).decode("utf-8")
    return (scope, capsule.provenance_class.value)


def run_delta_encode_stage(state: StageInputState) -> StageOutcome:
    """Delta-encode near-duplicates within one privacy scope and provenance
    class; every recorded delta carries an in-stage byte-exact proof."""

    _validate_state(state, StageKind.SEMANTIC_DELTA_ENCODING)
    groups: dict[tuple[str, str], list[SnapshotItem]] = {}
    for item in _sorted_items(state.items):
        groups.setdefault(_delta_group_key(item.capsule), []).append(item)

    artifacts: list[StageArtifact] = []
    proposals: list[PendingLineageProposal] = []
    for key in sorted(groups):
        members = groups[key]
        previous: SnapshotItem | None = None
        previous_depth = 0
        for item in members:
            capsule = item.capsule
            if previous is None:
                previous = item
                previous_depth = state.delta_depths.get(capsule.capsule_id, 0)
                continue
            base = previous.capsule
            if previous_depth + 1 > DELTA_CHAIN_MAX_DEPTH:
                # Depth bound: rebase to full canonical bytes with proof.
                artifacts.append(
                    _artifact(
                        "rebase_artifact",
                        {
                            "byte_length": len(capsule.canonical_bytes),
                            "capsule_id": capsule.capsule_id,
                            "chain_depth": 0,
                            "equal": True,
                            "recomputed_sha256": sha256_hex(capsule.canonical_bytes),
                            "target_sha256": capsule.canonical_sha256,
                        },
                    )
                )
                previous = item
                previous_depth = 0
                continue
            patch = encode_delta(base, capsule)
            patch_bytes = canonicalize(patch)
            if (
                len(patch["operations"]) > MAX_DELTA_OPERATIONS
                or len(patch_bytes) > len(capsule.canonical_bytes)
            ):
                # Size bound: a patch larger than its target stores the
                # full capsule instead; nothing is encoded.
                artifacts.append(
                    _artifact(
                        "full_retention",
                        {
                            "capsule_id": capsule.capsule_id,
                            "reason": "patch_exceeds_target",
                            "target_sha256": capsule.canonical_sha256,
                        },
                    )
                )
                previous = item
                previous_depth = 0
                continue
            try:
                proof = verify_reconstruction(
                    base.canonical_bytes, patch, capsule.canonical_sha256
                )
            except MetabolismStageRejection as error:
                # Fail closed: the capsule stays fully resident with a
                # typed failure receipt; no artifact replaces anything.
                artifacts.append(
                    _artifact(
                        "reconstruction_failure",
                        {
                            "base_capsule_id": base.capsule_id,
                            "capsule_id": capsule.capsule_id,
                            "code": error.code,
                            "target_sha256": capsule.canonical_sha256,
                        },
                    )
                )
                previous = item
                previous_depth = 0
                continue
            depth = previous_depth + 1
            artifacts.append(
                _artifact(
                    "delta_artifact",
                    {
                        "base_capsule_id": base.capsule_id,
                        "base_sha256": base.canonical_sha256,
                        "chain_depth": depth,
                        "patch": patch,
                        "privacy_scope": dict(capsule.privacy_scope),
                        "target_capsule_id": capsule.capsule_id,
                        "target_sha256": capsule.canonical_sha256,
                    },
                )
            )
            artifacts.append(
                _artifact(
                    "reconstruction_proof",
                    {
                        **proof,
                        "base_capsule_id": base.capsule_id,
                        "stage": StageKind.SEMANTIC_DELTA_ENCODING.value,
                        "target_capsule_id": capsule.capsule_id,
                    },
                )
            )
            proposals.append(
                _proposal(
                    capsule.capsule_id,
                    (base.capsule_id,),
                    StageKind.SEMANTIC_DELTA_ENCODING,
                )
            )
            previous = item
            previous_depth = depth

    # Delta encoding proposes storage changes only: every capsule remains in
    # the resident working set until the 12-12 gates seal any replacement.
    return _outcome(
        StageKind.SEMANTIC_DELTA_ENCODING,
        state,
        _sorted_items(state.items),
        tuple(artifacts),
        tuple(proposals),
    )


# ---------------------------------------------------------------------------
# Stage 2: deterministic prototype-plus-exception clustering
# ---------------------------------------------------------------------------


def capsule_feature_tuple(capsule: MemoryCapsule) -> tuple[int, ...]:
    """Map one capsule to the closed fixed-length integer feature tuple."""

    if not isinstance(capsule, MemoryCapsule):
        _reject("stage_input_invalid")
    scope_kind = str(capsule.privacy_scope["scope_kind"])
    return (
        _SCOPE_KIND_ORDINALS[scope_kind],
        _digest_bucket(canonicalize(dict(capsule.privacy_scope)), SCOPE_BUCKET_MODULUS),
        _PROVENANCE_ORDINALS[capsule.provenance_class],
        0 if capsule.prediction is None else 1,
        0 if capsule.outcome is None else 1,
        0 if capsule.surprise is None else 1,
        len(capsule.alternatives),
        len(capsule.changed_beliefs),
        _digest_bucket(capsule.action.encode("utf-8"), ACTION_BUCKET_MODULUS),
    )


def feature_distance(left: tuple[int, ...], right: tuple[int, ...]) -> Fraction:
    """Exact per-component weighted absolute distance; int/Fraction only."""

    if len(left) != len(CLUSTER_FEATURE_WEIGHTS) or len(right) != len(
        CLUSTER_FEATURE_WEIGHTS
    ):
        _reject("stage_input_invalid")
    total = Fraction(0)
    for weight, a, b in zip(CLUSTER_FEATURE_WEIGHTS, left, right):
        if type(a) is not int or type(b) is not int:
            _reject("stage_input_invalid")
        total += weight * abs(a - b)
    return total


def _is_counterevidence(capsule: MemoryCapsule) -> bool:
    """The closed contradiction mark: a present surprise records that the
    outcome contradicted the prediction; such members are never absorbed."""

    return capsule.surprise is not None


def run_cluster_stage(state: StageInputState) -> StageOutcome:
    """Single deterministic pass in ascending content-identity order over
    closed integer features with exact Fraction distances."""

    _validate_state(state, StageKind.PROTOTYPE_EXCEPTION_CLUSTERING)
    ordered = _sorted_items(state.items)
    features = {
        item.capsule.capsule_id: capsule_feature_tuple(item.capsule) for item in ordered
    }
    # Each cluster: founder capsule_id plus member items, founded in sorted
    # content-identity order; joining ties break on lowest founder identity.
    clusters: list[tuple[str, list[SnapshotItem]]] = []
    for item in ordered:
        feature = features[item.capsule.capsule_id]
        qualifying = [
            founder
            for founder, _members in clusters
            if feature_distance(feature, features[founder]) <= CLUSTER_DISTANCE_THRESHOLD
        ]
        if qualifying:
            chosen = min(qualifying)
            for founder, members in clusters:
                if founder == chosen:
                    members.append(item)
                    break
        else:
            clusters.append((item.capsule.capsule_id, [item]))

    artifacts: list[StageArtifact] = []
    for founder, members in sorted(clusters):
        member_ids = sorted(item.capsule.capsule_id for item in members)
        # Prototype: minimal total intra-cluster distance, ties on lowest id.
        best_id = ""
        best_total: Fraction | None = None
        for candidate in member_ids:
            total = Fraction(0)
            for other in member_ids:
                total += feature_distance(features[candidate], features[other])
            if best_total is None or total < best_total or (
                total == best_total and candidate < best_id
            ):
                best_total = total
                best_id = candidate
        prototype_feature = features[best_id]
        capsules_by_id = {item.capsule.capsule_id: item.capsule for item in members}
        exceptions: list[dict[str, Any]] = []
        for member_id in member_ids:
            if member_id == best_id:
                continue
            distance = feature_distance(features[member_id], prototype_feature)
            counterevidence = _is_counterevidence(capsules_by_id[member_id])
            if distance != 0 or counterevidence:
                exceptions.append(
                    {
                        "capsule_id": member_id,
                        "counterevidence": counterevidence,
                        "distance": str(distance),
                        "divergence": [
                            features[member_id][index] - prototype_feature[index]
                            for index in range(len(CLUSTER_FEATURE_NAMES))
                        ],
                    }
                )
        artifacts.append(
            _artifact(
                "cluster_record",
                {
                    "cluster_profile_id": CLUSTER_PROFILE_ID,
                    "distance_threshold": str(CLUSTER_DISTANCE_THRESHOLD),
                    "exceptions": exceptions,
                    "feature_names": list(CLUSTER_FEATURE_NAMES),
                    "feature_weights": [str(weight) for weight in CLUSTER_FEATURE_WEIGHTS],
                    "founder_capsule_id": founder,
                    "member_capsule_ids": member_ids,
                    "prototype_capsule_id": best_id,
                    "prototype_feature": list(prototype_feature),
                },
            )
        )

    return _outcome(
        StageKind.PROTOTYPE_EXCEPTION_CLUSTERING,
        state,
        ordered,
        tuple(artifacts),
        (),
    )


# ---------------------------------------------------------------------------
# Stage 3: causal/procedural crystallization
# ---------------------------------------------------------------------------


def _fraction_string(numerator: int, denominator: int) -> str:
    return str(Fraction(numerator, denominator))


def _crystallize_candidate(
    record: Mapping[str, Any], capsules: Mapping[str, MemoryCapsule]
) -> StageArtifact:
    member_ids = [str(member) for member in record["member_capsule_ids"]]
    exception_ids = sorted(
        str(exception["capsule_id"]) for exception in record["exceptions"]
    )
    members = [capsules[member_id] for member_id in member_ids]
    total = len(members)
    common: dict[str, Any] = {
        "cluster_profile_id": CLUSTER_PROFILE_ID,
        "cluster_record_id": str(record["artifact_id"]),
        "exception_capsule_ids": exception_ids,
        "gate_receipt_id": NONE_SENTINEL,
        "source_capsule_ids": sorted(member_ids),
        "support": total,
    }
    actions = sorted({capsule.action for capsule in members})
    if len(actions) == 1:
        outcomes = sorted(
            {capsule.outcome for capsule in members if capsule.outcome is not None}
        )
        preconditions = sorted({capsule.state_before for capsule in members})
        return _artifact(
            "compressed_procedure",
            {
                **common,
                "expected_outcomes": outcomes,
                "preconditions": preconditions,
                "steps": actions,
            },
        )
    prediction_present = sum(
        1 for capsule in members if capsule.prediction is not None
    )
    outcome_present = sum(1 for capsule in members if capsule.outcome is not None)
    surprise_present = sum(1 for capsule in members if capsule.surprise is not None)
    belief_counts: dict[str, int] = {}
    for capsule in members:
        for belief in capsule.changed_beliefs:
            belief_counts[belief] = belief_counts.get(belief, 0) + 1
    return _artifact(
        "compressed_concept",
        {
            **common,
            "changed_belief_tallies": [
                {"belief": belief, "count": belief_counts[belief]}
                for belief in sorted(belief_counts)
            ],
            "ratios": {
                "outcome_ratio": _fraction_string(outcome_present, total),
                "prediction_ratio": _fraction_string(prediction_present, total),
                "surprise_ratio": _fraction_string(surprise_present, total),
            },
            "tallies": {
                "members_total": total,
                "outcome_present": outcome_present,
                "prediction_present": prediction_present,
                "surprise_present": surprise_present,
            },
        },
    )


def run_crystallize_stage(state: StageInputState) -> StageOutcome:
    """Compile qualifying clusters into gate-pending candidate documents
    carrying complete sorted source lineage; sources remain resident."""

    _validate_state(state, StageKind.CRYSTALLIZATION)
    ordered = _sorted_items(state.items)
    capsules = {item.capsule.capsule_id: item.capsule for item in ordered}
    cluster_records: list[Mapping[str, Any]] = []
    for artifact in state.artifacts:
        if not isinstance(artifact, StageArtifact):
            _reject("stage_input_invalid")
        if artifact.artifact_kind != "cluster_record":
            continue
        # Re-authenticate the carried record: its content identity must
        # recompute exactly from its canonical bytes.
        body = {key: _thawed(item) for key, item in artifact.value.items()}
        expected = compute_phase12_identity(
            SKELETON_PHASE12_STAGE_ARTIFACT_V1, "artifact_id", body
        )
        if expected != artifact.artifact_id or canonicalize(body) != artifact.canonical_bytes:
            _reject("stage_artifact_identity_mismatch")
        cluster_records.append(body)

    artifacts: list[StageArtifact] = []
    proposals: list[PendingLineageProposal] = []
    for record in sorted(cluster_records, key=lambda body: str(body["artifact_id"])):
        member_ids = [str(member) for member in record["member_capsule_ids"]]
        for member_id in member_ids:
            if member_id not in capsules:
                _reject("crystallize_unknown_member")
        for exception in record["exceptions"]:
            if str(exception["capsule_id"]) not in member_ids:
                _reject("crystallize_unknown_member")
        if len(member_ids) < CRYSTALLIZE_MIN_SUPPORT:
            continue
        candidate = _crystallize_candidate(record, capsules)
        try:
            scan_memory_document(
                {key: _thawed(item) for key, item in candidate.value.items()},
                schema_id=STAGE_ARTIFACT_SCHEMA_ID,
                source_event_id=str(record["artifact_id"]),
            )
        except MemorySafetyRejection as error:
            # Safety rejection defers the whole cluster with a typed
            # receipt; no candidate is emitted and no field is stripped.
            artifacts.append(
                _artifact(
                    "crystallization_deferral",
                    {
                        "category": error.metadata.category.value,
                        "cluster_record_id": str(record["artifact_id"]),
                        "reason": "safety_hold",
                        "rule_id": error.metadata.rule_id,
                    },
                )
            )
            continue
        artifacts.append(candidate)
        proposals.append(
            _proposal(candidate.artifact_id, member_ids, StageKind.CRYSTALLIZATION)
        )

    return _outcome(
        StageKind.CRYSTALLIZATION,
        state,
        ordered,
        tuple(artifacts),
        tuple(proposals),
    )


def _thawed(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thawed(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thawed(item) for item in value]
    return value


# ---------------------------------------------------------------------------
# Executor registry, pipeline chaining, and the sole commit path
# ---------------------------------------------------------------------------

METABOLISM_STAGE_EXECUTORS: Mapping[StageKind, StageExecutor] = MappingProxyType(
    {
        StageKind.LOSSLESS_DEDUPLICATION: run_deduplicate_stage,
        StageKind.SEMANTIC_DELTA_ENCODING: run_delta_encode_stage,
        StageKind.PROTOTYPE_EXCEPTION_CLUSTERING: run_cluster_stage,
        StageKind.CRYSTALLIZATION: run_crystallize_stage,
    }
)


def run_metabolism_stages(state: StageInputState) -> tuple[StageOutcome, ...]:
    """Run the four implemented stages in frozen order, chaining each stage's
    retained items and receipt identity into the next stage's input."""

    _validate_state(state, StageKind.LOSSLESS_DEDUPLICATION)
    outcomes: list[StageOutcome] = []
    current = state
    for stage in METABOLISM_STAGE_ORDER:
        outcome = METABOLISM_STAGE_EXECUTORS[stage](current)
        outcomes.append(outcome)
        carried = (
            tuple(
                artifact
                for artifact in outcome.artifacts
                if artifact.artifact_kind == "cluster_record"
            )
            if stage is StageKind.PROTOTYPE_EXCEPTION_CLUSTERING
            else ()
        )
        current = StageInputState(
            items=outcome.items_out,
            cycle_ordinal=state.cycle_ordinal,
            cycle_input_root=state.cycle_input_root,
            fence_id=state.fence_id,
            generation=state.generation,
            attempt_ordinal=state.attempt_ordinal,
            prior_receipt_id=outcome.receipt_id,
            delta_depths=state.delta_depths,
            artifacts=carried,
        )
    return tuple(outcomes)


def stage_receipt_append(outcome: StageOutcome, *, recorded_at: str) -> StageReceiptAppend:
    """Build the append-only store row for one stage receipt.

    ``recorded_at`` is caller-provided canonical UTC text: this module never
    reads a wall clock, and the sealed receipt bytes carry no timestamp.
    """

    if not isinstance(outcome, StageOutcome):
        _reject("stage_input_invalid")
    return StageReceiptAppend(
        stage_receipt_id=outcome.receipt_row_id,
        cycle_ordinal=int(outcome.receipt_value["cycle_ordinal"]),
        stage_name=outcome.stage.value,
        input_root=outcome.input_root,
        output_root=outcome.output_root,
        fence_id=str(outcome.receipt_value["fence_id"]),
        generation=int(outcome.receipt_value["generation"]),
        attempt_ordinal=int(outcome.receipt_value["attempt_ordinal"]),
        recorded_at=recorded_at,
        canonical_bytes=outcome.receipt_bytes,
    )


def commit_stage_outcome(
    store: StageStore,
    outcome: StageOutcome,
    *,
    writer_id: str,
    operation_id: str,
    recorded_at: str,
) -> OperationReceipt:
    """Append one stage receipt through the sole-writer store handle.

    This is the module's only store interaction: an append.  No update,
    delete, disposition, tombstone, or replacement path exists here.
    """

    item = stage_receipt_append(outcome, recorded_at=recorded_at)
    return store.append_stage_receipt(
        item, writer_id=writer_id, operation_id=operation_id
    )


__all__ = [
    "ACTION_BUCKET_MODULUS",
    "CLOSED_STAGE_ARTIFACT_KINDS",
    "CLOSED_STAGE_REJECTION_CODES",
    "CLUSTER_DISTANCE_THRESHOLD",
    "CLUSTER_FEATURE_NAMES",
    "CLUSTER_FEATURE_WEIGHTS",
    "CLUSTER_PROFILE_ID",
    "CRYSTALLIZE_MIN_SUPPORT",
    "DELTA_CHAIN_MAX_DEPTH",
    "DELTA_MIN_COPY_LENGTH",
    "DELTA_PATCH_SCHEMA_VERSION",
    "LINEAGE_PROPOSAL_SCHEMA_VERSION",
    "MAX_DELTA_OPERATIONS",
    "METABOLISM_STAGE_EXECUTORS",
    "METABOLISM_STAGE_ORDER",
    "MetabolismStageRejection",
    "PENDING_STATUS",
    "PendingLineageProposal",
    "SCOPE_BUCKET_MODULUS",
    "SKELETON_PHASE12_FEATURE_BUCKET_V1",
    "SKELETON_PHASE12_LINEAGE_PROPOSAL_V1",
    "SKELETON_PHASE12_STAGE_ARTIFACT_V1",
    "SKELETON_PHASE12_STAGE_ITEMS_V1",
    "SKELETON_PHASE12_STAGE_RECEIPT_V1",
    "STAGE_ARTIFACT_SCHEMA_ID",
    "STAGE_ARTIFACT_SCHEMA_VERSION",
    "STAGE_RECEIPT_SCHEMA_VERSION",
    "SnapshotItem",
    "StageArtifact",
    "StageExecutor",
    "StageInputState",
    "StageOutcome",
    "StageStore",
    "apply_delta",
    "capsule_feature_tuple",
    "commit_stage_outcome",
    "encode_delta",
    "feature_distance",
    "finalize_lineage_document",
    "reconstruct_chain",
    "run_cluster_stage",
    "run_crystallize_stage",
    "run_deduplicate_stage",
    "run_delta_encode_stage",
    "run_metabolism_stages",
    "stage_receipt_append",
    "verify_reconstruction",
]
