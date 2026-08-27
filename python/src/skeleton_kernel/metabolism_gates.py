"""The five Phase 12 compression-replacement gates (Plan 12-12, D-11..D-13).

``CompressionGateRunner`` is the sole authority that can turn a pending
lineage proposal (emitted gate-pending by ``metabolism_stages``) into a
sealed, schema-valid ``compression-lineage`` document.  For each proposal it:

1. Draws a seedless deterministic sample of source capsules: the
   ``GATE_SAMPLE_SIZE`` lowest length-framed SHA-256 digests of
   ``(cycle_input_root, capsule_id)`` under the frozen domain
   ``SKELETON_PHASE12_GATE_SAMPLE_V1``.  Ties are impossible by digest
   uniqueness and the selection is independent of insertion order.

2. Runs the five closed gates in frozen order — ``reconstruction``,
   ``decision_replay``, ``counterevidence_preservation``, ``provenance``,
   ``future_model_readability`` — over the sampled sources, reusing the
   stage-module byte-exact proof functions for reconstruction.

3. Emits exactly one content-addressed gate-receipt document per proposal
   under ``SKELETON_PHASE12_GATE_RECEIPT_V1``, valid against the published
   ``memory-gate-receipt`` schema: ``complete`` when all five gates ran,
   ``partial`` with a typed cause when an evaluation short-circuited.

4. Two-phase replacement, fail-closed: only an all-pass complete receipt
   finalizes the proposal through ``finalize_lineage_document`` bound to the
   receipt identity; the lineage row is appended through the sole-writer
   store strictly after the receipt row.  Sources are retained as evidence
   (MEM-16) — nothing here deletes, tombstones, or disposes any capsule.

5. Any gate failure marks the proposal ``compression_exempt`` with the
   failing gate bound into the receipt; the exemption is durable within the
   runner: a later identical proposal short-circuits to the original exempt
   receipt with a typed code and no re-evaluation.

Deterministic and typed throughout: no wall clock, no randomness, no float,
no unsorted iteration; every rejection carries a closed snake_case code.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Protocol

from .canonical import canonicalize, sha256_hex
from .metabolism_stages import (
    DELTA_PATCH_SCHEMA_VERSION,
    LINEAGE_PROPOSAL_SCHEMA_VERSION,
    MetabolismStageRejection,
    PENDING_STATUS,
    PendingLineageProposal,
    SKELETON_PHASE12_LINEAGE_PROPOSAL_V1,
    SKELETON_PHASE12_STAGE_ARTIFACT_V1,
    STAGE_ARTIFACT_SCHEMA_VERSION,
    StageArtifact,
    finalize_lineage_document,
    verify_reconstruction,
)
from .metabolism_store import (
    GateReceiptAppend,
    LineageAppend,
    OperationReceipt,
    metabolism_record_identity,
)
from .metabolism_types import (
    GateKind,
    MemoryCapsule,
    MetabolismTypeRejection,
    NONE_SENTINEL,
    SAFE_INTEGER_MAX,
    capsule_from_raw,
    compute_phase12_identity,
)


# ---------------------------------------------------------------------------
# Frozen gate constants
# ---------------------------------------------------------------------------

GATE_RECEIPT_SCHEMA_VERSION = "skeleton.memory-gate-receipt.v1"
SKELETON_PHASE12_GATE_RECEIPT_V1 = "SKELETON_PHASE12_GATE_RECEIPT_V1"
SKELETON_PHASE12_GATE_SAMPLE_V1 = "SKELETON_PHASE12_GATE_SAMPLE_V1"

# Versioned frozen sample bound: a proposal with more sources than this
# samples exactly the GATE_SAMPLE_SIZE lowest framed digests; a proposal
# with fewer samples every source.  The receipt's declared sample_size is
# always the exact count actually sampled, as in the sealed fixture corpus.
GATE_SAMPLE_SIZE = 3
GATE_SAMPLE_DERIVATION = "lowest_framed_digest"
GATE_SAMPLE_DERIVATION_INPUTS = ("cycle_input_root", "capsule_id")

# The closed five-gate evaluation order (D-11), identical to the published
# schema's compressionGate enum order.
COMPRESSION_GATE_ORDER = (
    GateKind.RECONSTRUCTION,
    GateKind.DECISION_REPLAY,
    GateKind.COUNTEREVIDENCE_PRESERVATION,
    GateKind.PROVENANCE,
    GateKind.FUTURE_MODEL_READABILITY,
)

COMPLETENESS_COMPLETE = "complete"
COMPLETENESS_PARTIAL = "partial"

GATE_STATUS_FINALIZED = "finalized"
GATE_STATUS_EXEMPT = "compression_exempt"
GATE_STATUS_DEFERRED = "deferred"
CLOSED_GATE_STATUSES = (
    GATE_STATUS_EXEMPT,
    GATE_STATUS_DEFERRED,
    GATE_STATUS_FINALIZED,
)

# The two semantic-compression candidate kinds the gates may seal.
GATED_ARTIFACT_KINDS = ("compressed_concept", "compressed_procedure")

# Closed member allowlists for future_model_readability: the compressed
# document is self-describing through exactly these members and nothing
# else — any extra member is a model-specific opaque smuggle and fails.
_COMMON_ARTIFACT_MEMBERS = frozenset(
    {
        "schema_version",
        "record_type",
        "artifact_id",
        "cluster_profile_id",
        "cluster_record_id",
        "exception_capsule_ids",
        "gate_receipt_id",
        "source_capsule_ids",
        "support",
    }
)
GATED_ARTIFACT_MEMBER_ALLOWLIST: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "compressed_procedure": frozenset(
            _COMMON_ARTIFACT_MEMBERS
            | {"expected_outcomes", "preconditions", "steps"}
        ),
        "compressed_concept": frozenset(
            _COMMON_ARTIFACT_MEMBERS
            | {"changed_belief_tallies", "ratios", "tallies"}
        ),
    }
)

CLOSED_GATE_REJECTION_CODES = (
    "gate_artifact_identity_mismatch",
    "gate_artifact_kind_unsupported",
    "gate_batch_duplicate_proposal",
    "gate_input_invalid",
    "gate_lineage_append_forbidden",
    "gate_lineage_operation_missing",
    "gate_outcome_invalid",
    "gate_proposal_artifact_mismatch",
    "gate_proposal_invalid",
    "gate_sample_input_invalid",
    "gate_source_capsule_missing",
)

CLOSED_GATE_OUTCOME_CODES = (
    "compression_exemption_durable",
    "gate_counterevidence_inventory_invalid",
    "gate_failed_counterevidence_preservation",
    "gate_failed_decision_replay",
    "gate_failed_future_model_readability",
    "gate_failed_provenance",
    "gate_failed_reconstruction",
    "gate_provenance_inventory_invalid",
    "gate_replay_projection_invalid",
    "gates_all_passed",
)


class MetabolismGateRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise MetabolismGateRejection(code)


class _GateShortCircuit(Exception):
    """Internal: a gate could not evaluate to a verdict; typed cause only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


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


def _float_free(value: Any) -> bool:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return True
    if isinstance(value, float):
        return False
    if isinstance(value, int):
        return -SAFE_INTEGER_MAX <= value <= SAFE_INTEGER_MAX
    if isinstance(value, Mapping):
        return all(_float_free(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return all(_float_free(item) for item in value)
    return False


# ---------------------------------------------------------------------------
# Deterministic digest-ordered sampling
# ---------------------------------------------------------------------------


def gate_sample_digest(cycle_input_root: str, capsule_id: str) -> str:
    """The framed sample-ordering digest of one ``(cycle_input_root, capsule_id)``."""

    if not _is_sha256(cycle_input_root) or not _is_sha256(capsule_id):
        _reject("gate_sample_input_invalid")
    return _framed_digest(
        SKELETON_PHASE12_GATE_SAMPLE_V1,
        canonicalize([cycle_input_root, capsule_id]),
    )


def draw_gate_sample(
    cycle_input_root: str, capsule_ids: Sequence[str]
) -> tuple[str, ...]:
    """Select the ``GATE_SAMPLE_SIZE`` lowest framed digests, seedlessly.

    The returned inventory is sorted lexicographically by capsule identity
    (the receipt's declared ordering); selection itself orders by digest,
    where ties are impossible because the framed digests of distinct
    capsule identities are distinct.  Insertion order never matters.
    """

    if not _is_sha256(cycle_input_root):
        _reject("gate_sample_input_invalid")
    if not isinstance(capsule_ids, (list, tuple)) or not capsule_ids:
        _reject("gate_sample_input_invalid")
    unique = set()
    for capsule_id in capsule_ids:
        if not _is_sha256(capsule_id) or capsule_id in unique:
            _reject("gate_sample_input_invalid")
        unique.add(capsule_id)
    ranked = sorted(
        (gate_sample_digest(cycle_input_root, capsule_id), capsule_id)
        for capsule_id in unique
    )
    selected = tuple(capsule_id for _digest, capsule_id in ranked[:GATE_SAMPLE_SIZE])
    return tuple(sorted(selected))


# ---------------------------------------------------------------------------
# Typed gate values
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GateProposalInput:
    """One gate-evaluation unit: a pending proposal, its compressed child
    document, and the retained source capsules covering every parent."""

    proposal: PendingLineageProposal
    artifact: StageArtifact
    capsules: Mapping[str, MemoryCapsule]


@dataclass(frozen=True, slots=True)
class GateResult:
    """One gate's exact integer accounting over the sampled sources."""

    gate: GateKind
    passed_count: int
    failed_count: int
    verdict: str


@dataclass(frozen=True, slots=True)
class GateOutcome:
    """The complete deterministic result of gating one proposal."""

    proposal_id: str
    artifact_id: str
    status: str
    code: str
    short_circuit: bool
    short_circuit_gate: GateKind | None
    sampled_capsule_ids: tuple[str, ...]
    gate_results: tuple[GateResult, ...]
    failed_gates: tuple[GateKind, ...]
    exempt_capsule_ids: tuple[str, ...]
    completeness: str
    receipt_value: Mapping[str, Any]
    receipt_bytes: bytes
    receipt_id: str
    receipt_row_id: str
    lineage_bytes: bytes | None


class GateStore(Protocol):
    """The narrow append-only store handle the gate commit path uses."""

    def append_gate_receipt(
        self, item: GateReceiptAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt: ...

    def append_lineage(
        self, item: LineageAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt: ...


# ---------------------------------------------------------------------------
# Fail-closed input authentication
# ---------------------------------------------------------------------------


def _bounded_int(value: object, minimum: int, code: str) -> int:
    if type(value) is not int or not minimum <= value <= SAFE_INTEGER_MAX:
        _reject(code)
    return int(value)


def _authenticate_proposal(proposal: PendingLineageProposal) -> None:
    """Recompute the proposal's content identity before trusting any field."""

    if not isinstance(proposal, PendingLineageProposal):
        _reject("gate_proposal_invalid")
    if proposal.status != PENDING_STATUS:
        _reject("gate_proposal_invalid")
    parents = proposal.parent_ids
    if (
        not isinstance(parents, tuple)
        or not parents
        or parents != tuple(sorted(set(parents)))
        or not all(_is_sha256(parent) for parent in parents)
    ):
        _reject("gate_proposal_invalid")
    if not _is_sha256(proposal.child_id) or proposal.child_id in parents:
        _reject("gate_proposal_invalid")
    value: dict[str, Any] = {
        "schema_version": LINEAGE_PROPOSAL_SCHEMA_VERSION,
        "record_type": "compression_lineage_proposal",
        "child_id": proposal.child_id,
        "parent_ids": list(parents),
        "producing_stage": proposal.producing_stage.value,
        "status": proposal.status,
    }
    expected = compute_phase12_identity(
        SKELETON_PHASE12_LINEAGE_PROPOSAL_V1, "proposal_id", value
    )
    if expected != proposal.proposal_id:
        _reject("gate_proposal_invalid")
    value["proposal_id"] = expected
    if canonicalize(value) != proposal.canonical_bytes:
        _reject("gate_proposal_invalid")


def _authenticate_artifact(artifact: StageArtifact) -> dict[str, Any]:
    """Re-authenticate the compressed child document's content identity."""

    if not isinstance(artifact, StageArtifact):
        _reject("gate_input_invalid")
    if artifact.artifact_kind not in GATED_ARTIFACT_KINDS:
        _reject("gate_artifact_kind_unsupported")
    body = _thaw(artifact.value)
    if not isinstance(body, dict) or body.get("record_type") != artifact.artifact_kind:
        _reject("gate_artifact_identity_mismatch")
    expected = compute_phase12_identity(
        SKELETON_PHASE12_STAGE_ARTIFACT_V1, "artifact_id", body
    )
    if expected != artifact.artifact_id:
        _reject("gate_artifact_identity_mismatch")
    if canonicalize(body) != artifact.canonical_bytes:
        _reject("gate_artifact_identity_mismatch")
    return body


def _validate_input(item: GateProposalInput) -> dict[str, Any]:
    if not isinstance(item, GateProposalInput):
        _reject("gate_input_invalid")
    _authenticate_proposal(item.proposal)
    body = _authenticate_artifact(item.artifact)
    if item.artifact.artifact_id != item.proposal.child_id:
        _reject("gate_proposal_artifact_mismatch")
    if not isinstance(item.capsules, Mapping):
        _reject("gate_input_invalid")
    for parent_id in item.proposal.parent_ids:
        capsule = item.capsules.get(parent_id)
        if capsule is None:
            _reject("gate_source_capsule_missing")
        if not isinstance(capsule, MemoryCapsule) or capsule.capsule_id != parent_id:
            _reject("gate_input_invalid")
    return body


# ---------------------------------------------------------------------------
# The five closed gate evaluators
# ---------------------------------------------------------------------------


def _reconstruction_failures(
    sample: tuple[str, ...], capsules: Mapping[str, MemoryCapsule]
) -> tuple[str, ...]:
    """Gate 1: byte-exact reproduction of every sampled source.

    Reuses the stage-module proof function: a whole-copy edit script must
    reproduce the retained canonical bytes to the declared digest, and the
    bytes must re-authenticate to the declared capsule identity.
    """

    failing: list[str] = []
    for capsule_id in sample:
        capsule = capsules[capsule_id]
        raw = capsule.canonical_bytes
        try:
            patch = {
                "schema_version": DELTA_PATCH_SCHEMA_VERSION,
                "operations": [{"op": "copy", "offset": 0, "length": len(raw)}],
            }
            verify_reconstruction(raw, patch, capsule.canonical_sha256)
            rebuilt = capsule_from_raw(raw)
        except (MetabolismStageRejection, MetabolismTypeRejection):
            failing.append(capsule_id)
            continue
        if rebuilt.capsule_id != capsule_id:
            failing.append(capsule_id)
    return tuple(sorted(failing))


def _text_inventory(value: object, code: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, str) for item in value
    ):
        raise _GateShortCircuit(code)
    return tuple(value)


def _decision_replay_failures(
    kind: str,
    body: Mapping[str, Any],
    sample: tuple[str, ...],
    capsules: Mapping[str, MemoryCapsule],
) -> tuple[str, ...]:
    """Gate 2: the closed deterministic replay comparison over capsule fields.

    A sampled capsule's recorded decision replays identically through the
    compressed form when every replay member of that form still represents
    the capsule's recorded fields exactly:

    ``compressed_procedure``: the recorded action is a step, the recorded
    state_before is a precondition, and a recorded outcome is an expected
    outcome.  ``compressed_concept``: every recorded changed belief appears
    in the belief tallies, and each present prediction/outcome/surprise is
    represented by a positive presence tally.  Malformed replay members
    cannot yield a verdict and short-circuit typed.
    """

    failing: list[str] = []
    if kind == "compressed_procedure":
        steps = _text_inventory(body.get("steps"), "gate_replay_projection_invalid")
        preconditions = _text_inventory(
            body.get("preconditions"), "gate_replay_projection_invalid"
        )
        expected_outcomes = _text_inventory(
            body.get("expected_outcomes"), "gate_replay_projection_invalid"
        )
        for capsule_id in sample:
            capsule = capsules[capsule_id]
            replayed = (
                capsule.action in steps
                and capsule.state_before in preconditions
                and (capsule.outcome is None or capsule.outcome in expected_outcomes)
            )
            if not replayed:
                failing.append(capsule_id)
        return tuple(sorted(failing))

    tallies = body.get("tallies")
    if not isinstance(tallies, Mapping) or not all(
        type(item) is int for item in tallies.values()
    ):
        raise _GateShortCircuit("gate_replay_projection_invalid")
    belief_entries = body.get("changed_belief_tallies")
    if not isinstance(belief_entries, (list, tuple)):
        raise _GateShortCircuit("gate_replay_projection_invalid")
    beliefs: set[str] = set()
    for entry in belief_entries:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("belief"), str):
            raise _GateShortCircuit("gate_replay_projection_invalid")
        if type(entry.get("count")) is not int or entry["count"] < 1:
            raise _GateShortCircuit("gate_replay_projection_invalid")
        beliefs.add(entry["belief"])
    for capsule_id in sample:
        capsule = capsules[capsule_id]
        replayed = all(belief in beliefs for belief in capsule.changed_beliefs)
        for field_value, tally_name in (
            (capsule.prediction, "prediction_present"),
            (capsule.outcome, "outcome_present"),
            (capsule.surprise, "surprise_present"),
        ):
            if field_value is not None and int(tallies.get(tally_name, 0)) < 1:
                replayed = False
        if not replayed:
            failing.append(capsule_id)
    return tuple(sorted(failing))


def _counterevidence_failures(
    body: Mapping[str, Any],
    sample: tuple[str, ...],
    capsules: Mapping[str, MemoryCapsule],
) -> tuple[str, ...]:
    """Gate 3: every sampled counterevidence-marked capsule (a present
    surprise) survives as an explicit exception, never absorbed."""

    exceptions_raw = body.get("exception_capsule_ids")
    if not isinstance(exceptions_raw, (list, tuple)) or not all(
        _is_sha256(item) for item in exceptions_raw
    ):
        raise _GateShortCircuit("gate_counterevidence_inventory_invalid")
    exceptions = set(exceptions_raw)
    failing = [
        capsule_id
        for capsule_id in sample
        if capsules[capsule_id].surprise is not None and capsule_id not in exceptions
    ]
    return tuple(sorted(failing))


def _provenance_failures(
    body: Mapping[str, Any],
    proposal: PendingLineageProposal,
    sample: tuple[str, ...],
) -> tuple[str, ...]:
    """Gate 4: the compressed document's source lineage covers exactly the
    proposal's parent set — no orphaned source, no smuggled extra."""

    sources_raw = body.get("source_capsule_ids")
    if not isinstance(sources_raw, (list, tuple)) or not all(
        _is_sha256(item) for item in sources_raw
    ):
        raise _GateShortCircuit("gate_provenance_inventory_invalid")
    sources = set(sources_raw)
    exact_cover = sources == set(proposal.parent_ids)
    failing = [
        capsule_id
        for capsule_id in sample
        if not exact_cover or capsule_id not in sources
    ]
    return tuple(sorted(failing))


def _future_readability_failures(
    artifact: StageArtifact,
    body: Mapping[str, Any],
    sample: tuple[str, ...],
) -> tuple[str, ...]:
    """Gate 5: the compressed document is future-model readable — it matches
    its published self-describing member closure exactly, stays gate-pending,
    and carries no float and no model-specific opaque member."""

    allowlist = GATED_ARTIFACT_MEMBER_ALLOWLIST[artifact.artifact_kind]
    readable = (
        set(body) == allowlist
        and body.get("schema_version") == STAGE_ARTIFACT_SCHEMA_VERSION
        and body.get("record_type") == artifact.artifact_kind
        and body.get("gate_receipt_id") == NONE_SENTINEL
        and type(body.get("support")) is int
        and _float_free(body)
    )
    if readable:
        return ()
    # Readability is a property of the whole document: an unreadable form
    # cannot replace any sampled source, so every sampled capsule fails.
    return tuple(sorted(sample))


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


class CompressionGateRunner:
    """Deterministic five-gate evaluator for pending lineage proposals."""

    __slots__ = (
        "_attempt_ordinal",
        "_cycle_input_root",
        "_cycle_ordinal",
        "_exemptions",
        "_fence_id",
        "_generation",
    )

    def __init__(
        self,
        *,
        cycle_ordinal: int,
        cycle_input_root: str,
        fence_id: str,
        generation: int,
        attempt_ordinal: int,
    ) -> None:
        self._cycle_ordinal = _bounded_int(cycle_ordinal, 0, "gate_input_invalid")
        self._generation = _bounded_int(generation, 0, "gate_input_invalid")
        self._attempt_ordinal = _bounded_int(attempt_ordinal, 1, "gate_input_invalid")
        if not _is_sha256(cycle_input_root) or not _is_sha256(fence_id):
            _reject("gate_input_invalid")
        self._cycle_input_root = str(cycle_input_root)
        self._fence_id = str(fence_id)
        # Durable exemption ledger: proposal identity -> the sealing exempt
        # outcome.  A later identical proposal (same content identity, hence
        # same child and source set) short-circuits typed to this outcome.
        self._exemptions: dict[str, GateOutcome] = {}

    @property
    def cycle_input_root(self) -> str:
        return self._cycle_input_root

    def run_batch(
        self, items: Sequence[GateProposalInput]
    ) -> tuple[GateOutcome, ...]:
        """Gate every proposal in the batch; duplicate proposals reject."""

        if not isinstance(items, (list, tuple)):
            _reject("gate_input_invalid")
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, GateProposalInput) or not isinstance(
                item.proposal, PendingLineageProposal
            ):
                _reject("gate_input_invalid")
            if item.proposal.proposal_id in seen:
                _reject("gate_batch_duplicate_proposal")
            seen.add(item.proposal.proposal_id)
        return tuple(self.run_proposal(item) for item in items)

    def run_proposal(self, item: GateProposalInput) -> GateOutcome:
        """Run the five gates over one proposal's deterministic sample."""

        body = _validate_input(item)
        proposal = item.proposal
        prior = self._exemptions.get(proposal.proposal_id)
        if prior is not None:
            # Durable exemption: short-circuit typed to the sealed receipt.
            return replace(
                prior,
                code="compression_exemption_durable",
                short_circuit=True,
            )

        sample = draw_gate_sample(self._cycle_input_root, proposal.parent_ids)
        results: list[GateResult] = []
        failed_gates: list[GateKind] = []
        exempt: set[str] = set()
        short_circuit_gate: GateKind | None = None
        short_circuit_code: str | None = None
        for gate in COMPRESSION_GATE_ORDER:
            try:
                if gate is GateKind.RECONSTRUCTION:
                    failing = _reconstruction_failures(sample, item.capsules)
                elif gate is GateKind.DECISION_REPLAY:
                    failing = _decision_replay_failures(
                        item.artifact.artifact_kind, body, sample, item.capsules
                    )
                elif gate is GateKind.COUNTEREVIDENCE_PRESERVATION:
                    failing = _counterevidence_failures(body, sample, item.capsules)
                elif gate is GateKind.PROVENANCE:
                    failing = _provenance_failures(body, proposal, sample)
                else:
                    failing = _future_readability_failures(item.artifact, body, sample)
            except _GateShortCircuit as cause:
                short_circuit_gate = gate
                short_circuit_code = cause.code
                break
            failed_count = len(failing)
            results.append(
                GateResult(
                    gate=gate,
                    passed_count=len(sample) - failed_count,
                    failed_count=failed_count,
                    verdict="failed" if failed_count else "passed",
                )
            )
            if failed_count:
                failed_gates.append(gate)
                exempt.update(failing)

        completeness = (
            COMPLETENESS_COMPLETE
            if len(results) == len(COMPRESSION_GATE_ORDER)
            else COMPLETENESS_PARTIAL
        )
        exempt_ids = tuple(sorted(exempt))
        receipt_value, receipt_bytes, receipt_id = self._seal_receipt(
            artifact_id=item.artifact.artifact_id,
            sample=sample,
            results=tuple(results),
            exempt_ids=exempt_ids,
            completeness=completeness,
        )

        if short_circuit_gate is not None:
            status = GATE_STATUS_DEFERRED
            code = str(short_circuit_code)
            lineage_bytes: bytes | None = None
        elif failed_gates:
            status = GATE_STATUS_EXEMPT
            code = f"gate_failed_{failed_gates[0].value}"
            lineage_bytes = None
        else:
            status = GATE_STATUS_FINALIZED
            code = "gates_all_passed"
            # Two-phase replacement, phase one product: the sealed lineage
            # bytes bind the proposal to this receipt's identity.  Sources
            # are retained as evidence (MEM-16); nothing is deleted here.
            lineage_bytes = finalize_lineage_document(proposal, receipt_id)

        outcome = GateOutcome(
            proposal_id=proposal.proposal_id,
            artifact_id=item.artifact.artifact_id,
            status=status,
            code=code,
            short_circuit=False,
            short_circuit_gate=short_circuit_gate,
            sampled_capsule_ids=sample,
            gate_results=tuple(results),
            failed_gates=tuple(failed_gates),
            exempt_capsule_ids=exempt_ids,
            completeness=completeness,
            receipt_value=receipt_value,
            receipt_bytes=receipt_bytes,
            receipt_id=receipt_id,
            receipt_row_id=metabolism_record_identity("gate_receipt", receipt_bytes),
            lineage_bytes=lineage_bytes,
        )
        if status == GATE_STATUS_EXEMPT:
            self._exemptions[proposal.proposal_id] = outcome
        return outcome

    def _seal_receipt(
        self,
        *,
        artifact_id: str,
        sample: tuple[str, ...],
        results: tuple[GateResult, ...],
        exempt_ids: tuple[str, ...],
        completeness: str,
    ) -> tuple[Mapping[str, Any], bytes, str]:
        value: dict[str, Any] = {
            "schema_version": GATE_RECEIPT_SCHEMA_VERSION,
            "record_type": "gate_receipt",
            "cycle_ordinal": self._cycle_ordinal,
            "cycle_input_root": self._cycle_input_root,
            "fence_id": self._fence_id,
            "generation": self._generation,
            "attempt_ordinal": self._attempt_ordinal,
            "artifact_id": artifact_id,
            "sample": {
                "derivation": GATE_SAMPLE_DERIVATION,
                "derivation_domain": SKELETON_PHASE12_GATE_SAMPLE_V1,
                "derivation_inputs": list(GATE_SAMPLE_DERIVATION_INPUTS),
                "sample_size": len(sample),
                "sampled_capsule_ids": list(sample),
            },
            "gate_results": [
                {
                    "gate": result.gate.value,
                    "passed_count": result.passed_count,
                    "failed_count": result.failed_count,
                    "verdict": result.verdict,
                }
                for result in results
            ],
            "exemptions": [
                {
                    "capsule_id": capsule_id,
                    "artifact_id": artifact_id,
                    "outcome": "compression_exempt",
                }
                for capsule_id in exempt_ids
            ],
            "completeness": completeness,
        }
        receipt_id = compute_phase12_identity(
            SKELETON_PHASE12_GATE_RECEIPT_V1, "gate_receipt_id", value
        )
        value["gate_receipt_id"] = receipt_id
        return _freeze(value), canonicalize(value), receipt_id


# ---------------------------------------------------------------------------
# Two-phase store commit: receipt first, verified lineage strictly after
# ---------------------------------------------------------------------------


def gate_receipt_append(outcome: GateOutcome, *, recorded_at: str) -> GateReceiptAppend:
    """Build the append-only store row for one sealed gate receipt.

    ``recorded_at`` is caller-provided canonical UTC text; the sealed
    receipt bytes carry no timestamp.  The row verdict is ``pass`` only for
    an all-pass complete receipt; the bound gate name is the first failing
    gate when one exists, otherwise the last gate that ran.
    """

    if not isinstance(outcome, GateOutcome) or not outcome.gate_results:
        _reject("gate_outcome_invalid")
    if outcome.failed_gates:
        gate_name = outcome.failed_gates[0].value
    else:
        gate_name = outcome.gate_results[-1].gate.value
    return GateReceiptAppend(
        gate_receipt_id=outcome.receipt_row_id,
        artifact_id=outcome.artifact_id,
        gate_name=gate_name,
        verdict="pass" if outcome.status == GATE_STATUS_FINALIZED else "fail",
        fence_id=str(outcome.receipt_value["fence_id"]),
        generation=int(outcome.receipt_value["generation"]),
        attempt_ordinal=int(outcome.receipt_value["attempt_ordinal"]),
        recorded_at=recorded_at,
        canonical_bytes=outcome.receipt_bytes,
    )


def gate_lineage_append(outcome: GateOutcome, *, recorded_at: str) -> LineageAppend:
    """Build the verified replacement lineage row for a finalized outcome."""

    if not isinstance(outcome, GateOutcome):
        _reject("gate_outcome_invalid")
    if outcome.status != GATE_STATUS_FINALIZED or outcome.lineage_bytes is None:
        _reject("gate_lineage_append_forbidden")
    return LineageAppend(
        lineage_bytes=outcome.lineage_bytes,
        fence_id=str(outcome.receipt_value["fence_id"]),
        generation=int(outcome.receipt_value["generation"]),
        attempt_ordinal=int(outcome.receipt_value["attempt_ordinal"]),
        recorded_at=recorded_at,
    )


def commit_gate_outcome(
    store: GateStore,
    outcome: GateOutcome,
    *,
    writer_id: str,
    receipt_operation_id: str,
    lineage_operation_id: str | None = None,
    recorded_at: str,
) -> tuple[OperationReceipt, OperationReceipt | None]:
    """Append the sealed receipt, then — for all-pass outcomes only — the
    verified replacement lineage referencing it, strictly in that order.

    This is the module's entire store interaction: two appends.  No update,
    delete, tombstone, or disposition path exists here; source capsules are
    retained as evidence per MEM-16 regardless of the outcome.
    """

    if not isinstance(outcome, GateOutcome):
        _reject("gate_outcome_invalid")
    if outcome.status == GATE_STATUS_FINALIZED:
        if lineage_operation_id is None:
            _reject("gate_lineage_operation_missing")
    elif lineage_operation_id is not None:
        _reject("gate_lineage_append_forbidden")
    receipt_result = store.append_gate_receipt(
        gate_receipt_append(outcome, recorded_at=recorded_at),
        writer_id=writer_id,
        operation_id=receipt_operation_id,
    )
    if outcome.status != GATE_STATUS_FINALIZED:
        return receipt_result, None
    lineage_result = store.append_lineage(
        gate_lineage_append(outcome, recorded_at=recorded_at),
        writer_id=writer_id,
        operation_id=str(lineage_operation_id),
    )
    return receipt_result, lineage_result


__all__ = [
    "CLOSED_GATE_OUTCOME_CODES",
    "CLOSED_GATE_REJECTION_CODES",
    "CLOSED_GATE_STATUSES",
    "COMPLETENESS_COMPLETE",
    "COMPLETENESS_PARTIAL",
    "COMPRESSION_GATE_ORDER",
    "CompressionGateRunner",
    "GATED_ARTIFACT_KINDS",
    "GATED_ARTIFACT_MEMBER_ALLOWLIST",
    "GATE_RECEIPT_SCHEMA_VERSION",
    "GATE_SAMPLE_DERIVATION",
    "GATE_SAMPLE_DERIVATION_INPUTS",
    "GATE_SAMPLE_SIZE",
    "GATE_STATUS_DEFERRED",
    "GATE_STATUS_EXEMPT",
    "GATE_STATUS_FINALIZED",
    "GateOutcome",
    "GateProposalInput",
    "GateResult",
    "GateStore",
    "MetabolismGateRejection",
    "SKELETON_PHASE12_GATE_RECEIPT_V1",
    "SKELETON_PHASE12_GATE_SAMPLE_V1",
    "commit_gate_outcome",
    "draw_gate_sample",
    "gate_lineage_append",
    "gate_receipt_append",
    "gate_sample_digest",
]
