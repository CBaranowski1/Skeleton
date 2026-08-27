"""One-way signed proposal membrane with rejection non-interference."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
from enum import StrEnum
from typing import Any

from .bootstrap_trust import ReleaseRootAnchor
from .canonical import canonicalize, parse_raw_json, sha256_hex
from .proposal import (
    ProposalRejection,
    ValidatedProposal,
    assert_proposal_fresh,
    parse_proposal_wire,
    register_proposal_replay,
)
from .schema_registry import SchemaRegistry
from .signing import (
    SigningRejection,
    _assert_release_root,
    verify_current_advisory_signer,
)
from .store import KernelStore


ZERO_HASH = "0" * 64
VALIDATION_ORDER = (
    "schema_protocol_wire",
    "root_signer",
    "signature",
    "expiry",
    "replay",
    "provenance",
    "command_free",
    "accepted",
)


class ProposalRejectionCode(StrEnum):
    PROPOSAL_WIRE_LENGTH_INVALID = "proposal_wire_length_invalid"
    MALFORMED_PROPOSAL_WIRE = "malformed_proposal_wire"
    NONCANONICAL_PROPOSAL_WIRE = "noncanonical_proposal_wire"
    INVALID_ENVELOPE_SHAPE = "invalid_envelope_shape"
    SCHEMA_INVALID = "schema_invalid"
    UNKNOWN_SIGNATURE_PROTOCOL = "unknown_signature_protocol"
    CROSS_CLASS = "cross_class"
    MALFORMED_SIGNER_KEY_ID = "malformed_signer_key_id"
    NONCANONICAL_EPOCH = "noncanonical_epoch"
    EPOCH_OUT_OF_RANGE = "epoch_out_of_range"
    MALFORMED_SIGNATURE_WIRE = "malformed_signature_wire"
    COMMAND_FORBIDDEN = "command_forbidden"
    AUTHENTICATED_RELEASE_ROOT_REQUIRED = "authenticated_release_root_required"
    TRUST_ROOT_MISMATCH = "trust_root_mismatch"
    SIGNER_STATE_ABSENT = "signer_state_absent"
    SIGNER_EPOCH_MISMATCH = "signer_epoch_mismatch"
    SIGNER_REVOKED = "signer_revoked"
    SIGNER_INACTIVE = "signer_inactive"
    MALFORMED_PUBLIC_KEY = "malformed_public_key"
    SIGNER_KEY_ID_MISMATCH = "signer_key_id_mismatch"
    SIGNATURE_INVALID = "signature_invalid"
    PROPOSAL_CREATED_AT_INVALID = "proposal_created_at_invalid"
    PROPOSAL_EXPIRES_AT_INVALID = "proposal_expires_at_invalid"
    PROPOSAL_NOW_INVALID = "proposal_now_invalid"
    PROPOSAL_TIME_INVALID = "proposal_time_invalid"
    PROPOSAL_NOT_YET_VALID = "proposal_not_yet_valid"
    PROPOSAL_EXPIRED = "proposal_expired"
    PROPOSAL_REPLAY = "proposal_replay"
    PROVENANCE_INVALID = "provenance_invalid"


@dataclass(frozen=True, slots=True)
class GenericAuthorityRequest:
    """Separately constructed advisory request with no executable operation."""

    request_id: str
    proposal_id: str
    project_id: str
    work_id: str
    experience_id: str
    policy_sha256: str
    recommendation_sha256: str
    evidence_sha256: tuple[str, ...]
    signer_key_id: str
    signer_set_epoch: str
    expires_at: str


@dataclass(frozen=True, slots=True)
class ProposalDecision:
    """Auditable D-14 outcome without payload, secret, or command echo."""

    accepted: bool
    rejection_code: ProposalRejectionCode | None
    validation_stage: str
    proposal_id: str | None
    signer_key_id: str | None
    signer_set_epoch: str | None
    signature_valid: bool
    expiry_valid: bool
    lineage_sha256: str
    evidence_sha256: str
    authority_state_before_sha256: str
    authority_state_after_sha256: str
    request: GenericAuthorityRequest | None
    audit_bytes: bytes


class ProposalMembrane:
    """Validate advisory bytes and construct, but never apply, a generic request."""

    __slots__ = ("_release_root", "_store", "_registry")

    def __init__(
        self,
        *,
        release_root: ReleaseRootAnchor,
        store: KernelStore,
        registry: SchemaRegistry,
    ) -> None:
        _assert_release_root(release_root)
        if not isinstance(store, KernelStore):
            raise TypeError("KernelStore required")
        if not isinstance(registry, SchemaRegistry):
            raise TypeError("authenticated SchemaRegistry required")
        self._release_root = release_root
        self._store = store
        self._registry = registry

    def evaluate(self, raw: bytes, *, now: str) -> ProposalDecision:
        full_before = self._store.logical_snapshot()
        authority_before = _authority_state_sha256(full_before)
        evidence_sha256 = (
            hashlib.sha256(raw).hexdigest()
            if isinstance(raw, bytes)
            else ZERO_HASH
        )
        proposal: ValidatedProposal | None = None
        signature_valid = False
        expiry_valid = False
        lineage_sha256 = ZERO_HASH
        try:
            proposal = parse_proposal_wire(raw, registry=self._registry)
            verify_current_advisory_signer(
                _thaw_json(proposal.envelope),
                release_root=self._release_root,
                store=self._store,
            )
            signature_valid = True
            assert_proposal_fresh(proposal, now=now)
            expiry_valid = True
            if self._store.connection.execute(
                "SELECT 1 FROM proposal_replay_ids WHERE proposal_id = ?",
                (proposal.proposal_id,),
            ).fetchone():
                raise ProposalRejection("proposal_replay")
            lineage_sha256 = _validate_provenance(proposal)
            _assert_command_free(proposal)
            request = _build_request(proposal, lineage_sha256)
            register_proposal_replay(
                self._store,
                proposal,
                accepted_at=now,
            )
            authority_after = _authority_state_sha256(
                self._store.logical_snapshot()
            )
            if authority_after != authority_before:
                raise RuntimeError("proposal_authority_interference")
            return _decision(
                accepted=True,
                code=None,
                stage="accepted",
                proposal=proposal,
                signature_valid=True,
                expiry_valid=True,
                lineage_sha256=lineage_sha256,
                evidence_sha256=evidence_sha256,
                authority_before=authority_before,
                authority_after=authority_after,
                request=request,
            )
        except (ProposalRejection, SigningRejection) as error:
            full_after = self._store.logical_snapshot()
            if full_after != full_before:
                raise RuntimeError("proposal_rejection_interference") from error
            code = ProposalRejectionCode(error.code)
            authority_after = _authority_state_sha256(full_after)
            return _decision(
                accepted=False,
                code=code,
                stage=_stage_for(code),
                proposal=proposal,
                signature_valid=signature_valid,
                expiry_valid=expiry_valid,
                lineage_sha256=lineage_sha256,
                evidence_sha256=evidence_sha256,
                authority_before=authority_before,
                authority_after=authority_after,
                request=None,
            )


def _authority_state_sha256(snapshot_bytes: bytes) -> str:
    snapshot = parse_raw_json(snapshot_bytes)
    if not isinstance(snapshot, dict):
        raise RuntimeError("invalid_store_snapshot")
    authority = dict(snapshot)
    authority.pop("proposal_replay_ids", None)
    return sha256_hex(canonicalize(authority))


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _validate_provenance(proposal: ValidatedProposal) -> str:
    body = proposal.body
    hash_fields = (
        "proposal_id",
        "work_id",
        "experience_id",
        "nonce",
        "policy_sha256",
    )
    if any(body.get(field) == ZERO_HASH for field in hash_fields):
        raise ProposalRejection("provenance_invalid")
    project_id = body.get("project_id")
    observations = body.get("observations")
    if (
        not isinstance(project_id, str)
        or not project_id
        or not isinstance(observations, tuple)
        or not observations
    ):
        raise ProposalRejection("provenance_invalid")
    evidence: list[str] = []
    for observation in observations:
        if not isinstance(observation, Mapping):
            raise ProposalRejection("provenance_invalid")
        digest = observation.get("evidence_sha256")
        if not isinstance(digest, str) or digest == ZERO_HASH:
            raise ProposalRejection("provenance_invalid")
        evidence.append(digest)
    lineage = {
        "experience_id": body["experience_id"],
        "evidence_sha256": evidence,
        "policy_sha256": body["policy_sha256"],
        "project_id": project_id,
        "proposal_id": proposal.proposal_id,
        "work_id": body["work_id"],
    }
    return sha256_hex(canonicalize(lineage))


def _assert_command_free(proposal: ValidatedProposal) -> None:
    forbidden = {
        "account",
        "action",
        "authority_command",
        "broker",
        "command",
        "credential",
        "effect",
        "executable",
        "mutation",
        "target_account",
    }

    def visit(value: Any) -> bool:
        if isinstance(value, Mapping):
            return any(key in forbidden or visit(item) for key, item in value.items())
        if isinstance(value, tuple):
            return any(visit(item) for item in value)
        return False

    if visit(proposal.envelope):
        raise ProposalRejection("command_forbidden")


def _build_request(
    proposal: ValidatedProposal,
    lineage_sha256: str,
) -> GenericAuthorityRequest:
    body = proposal.body
    observations = body["observations"]
    evidence = tuple(
        str(observation["evidence_sha256"])
        for observation in observations
        if isinstance(observation, Mapping)
    )
    recommendation_sha256 = sha256_hex(
        canonicalize(_thaw_json(body["recommendation"]))
    )
    request_input = {
        "evidence_sha256": list(evidence),
        "lineage_sha256": lineage_sha256,
        "proposal_id": proposal.proposal_id,
        "recommendation_sha256": recommendation_sha256,
        "signer_key_id": proposal.signer_key_id,
        "signer_set_epoch": proposal.signer_set_epoch,
    }
    return GenericAuthorityRequest(
        request_id=sha256_hex(canonicalize(request_input)),
        proposal_id=proposal.proposal_id,
        project_id=str(body["project_id"]),
        work_id=str(body["work_id"]),
        experience_id=str(body["experience_id"]),
        policy_sha256=str(body["policy_sha256"]),
        recommendation_sha256=recommendation_sha256,
        evidence_sha256=evidence,
        signer_key_id=proposal.signer_key_id,
        signer_set_epoch=proposal.signer_set_epoch,
        expires_at=str(body["expires_at"]),
    )


def _decision(
    *,
    accepted: bool,
    code: ProposalRejectionCode | None,
    stage: str,
    proposal: ValidatedProposal | None,
    signature_valid: bool,
    expiry_valid: bool,
    lineage_sha256: str,
    evidence_sha256: str,
    authority_before: str,
    authority_after: str,
    request: GenericAuthorityRequest | None,
) -> ProposalDecision:
    audit = {
        "accepted": accepted,
        "authority_state_after_sha256": authority_after,
        "authority_state_before_sha256": authority_before,
        "evidence_sha256": evidence_sha256,
        "expiry_valid": expiry_valid,
        "lineage_sha256": lineage_sha256,
        "proposal_id": proposal.proposal_id if proposal else None,
        "rejection_code": code.value if code else None,
        "request_id": request.request_id if request else None,
        "schema_version": "skeleton.proposal-membrane-decision.v1",
        "signature_valid": signature_valid,
        "signer_key_id": proposal.signer_key_id if proposal else None,
        "signer_set_epoch": proposal.signer_set_epoch if proposal else None,
        "validation_stage": stage,
    }
    audit_bytes = canonicalize(audit)
    return ProposalDecision(
        accepted=accepted,
        rejection_code=code,
        validation_stage=stage,
        proposal_id=proposal.proposal_id if proposal else None,
        signer_key_id=proposal.signer_key_id if proposal else None,
        signer_set_epoch=proposal.signer_set_epoch if proposal else None,
        signature_valid=signature_valid,
        expiry_valid=expiry_valid,
        lineage_sha256=lineage_sha256,
        evidence_sha256=evidence_sha256,
        authority_state_before_sha256=authority_before,
        authority_state_after_sha256=authority_after,
        request=request,
        audit_bytes=audit_bytes,
    )


def _stage_for(code: ProposalRejectionCode) -> str:
    if code in {
        ProposalRejectionCode.PROPOSAL_WIRE_LENGTH_INVALID,
        ProposalRejectionCode.MALFORMED_PROPOSAL_WIRE,
        ProposalRejectionCode.NONCANONICAL_PROPOSAL_WIRE,
        ProposalRejectionCode.INVALID_ENVELOPE_SHAPE,
        ProposalRejectionCode.SCHEMA_INVALID,
        ProposalRejectionCode.UNKNOWN_SIGNATURE_PROTOCOL,
        ProposalRejectionCode.CROSS_CLASS,
        ProposalRejectionCode.MALFORMED_SIGNER_KEY_ID,
        ProposalRejectionCode.NONCANONICAL_EPOCH,
        ProposalRejectionCode.EPOCH_OUT_OF_RANGE,
        ProposalRejectionCode.MALFORMED_SIGNATURE_WIRE,
        ProposalRejectionCode.COMMAND_FORBIDDEN,
    }:
        return "schema_protocol_wire"
    if code in {
        ProposalRejectionCode.AUTHENTICATED_RELEASE_ROOT_REQUIRED,
        ProposalRejectionCode.TRUST_ROOT_MISMATCH,
        ProposalRejectionCode.SIGNER_STATE_ABSENT,
        ProposalRejectionCode.SIGNER_EPOCH_MISMATCH,
        ProposalRejectionCode.SIGNER_REVOKED,
        ProposalRejectionCode.SIGNER_INACTIVE,
        ProposalRejectionCode.MALFORMED_PUBLIC_KEY,
        ProposalRejectionCode.SIGNER_KEY_ID_MISMATCH,
    }:
        return "root_signer"
    if code is ProposalRejectionCode.SIGNATURE_INVALID:
        return "signature"
    if code in {
        ProposalRejectionCode.PROPOSAL_CREATED_AT_INVALID,
        ProposalRejectionCode.PROPOSAL_EXPIRES_AT_INVALID,
        ProposalRejectionCode.PROPOSAL_NOW_INVALID,
        ProposalRejectionCode.PROPOSAL_TIME_INVALID,
        ProposalRejectionCode.PROPOSAL_NOT_YET_VALID,
        ProposalRejectionCode.PROPOSAL_EXPIRED,
    }:
        return "expiry"
    if code is ProposalRejectionCode.PROPOSAL_REPLAY:
        return "replay"
    if code is ProposalRejectionCode.PROVENANCE_INVALID:
        return "provenance"
    raise RuntimeError(f"unmapped proposal rejection code: {code.value}")
