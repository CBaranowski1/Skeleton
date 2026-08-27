"""Derived-artifact registry and isolated champion rebuild (MEM-19, D-19/D-20).

Every embedding, index, summary, cache, density field, and model-specific
hidden state is a registered, content-addressed, rebuildable projection of
authoritative memory.  This module owns:

* ``DerivedArtifactRegistry`` -- schema-valid, content-addressed registrations
  under ``SKELETON_PHASE12_DERIVED_ARTIFACT_V1`` with the required
  ``authority_input: false`` / ``rebuildable: true`` constants, sorted unique
  nonempty source roots, and a closed builder registry mapping deterministic
  builder identifiers to pure builder callables.
* ``rebuild_and_verify`` -- an isolated re-run of the registered builder over
  the exact source roots inside an offline-environment guard mirroring
  ``memory_rebuild.ChampionMemoryRebuilder``; the rebuilt bytes are compared
  in a fixed order and the first divergence is reported exactly, with the
  byte offset and a bounded context window, never averaged or skipped.
* ``verify_all`` -- a deterministic digest-ordered audit sweep producing
  per-artifact typed outcomes plus verified/diverged/unrebuildable counts.
* ``assert_not_authority_input`` -- the MEM-19 boundary: a registered derived
  artifact identity appearing anywhere inside a caller-supplied
  authority-relevant document is a typed rejection.

The module reads no wall clock, uses no floats, and derives every identity
from length-framed domain-separated SHA-256 over canonical bytes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
import os
import re
import socket
import sys
from types import MappingProxyType
from typing import Any, Callable, Iterator

from .canonical import canonicalize
from .metabolism_types import (
    DerivedArtifactKind,
    GENESIS_SHA256,
    SAFE_INTEGER_MAX,
    compute_phase12_identity,
)


DERIVED_ARTIFACT_SCHEMA_VERSION = "skeleton.memory-derived-artifact.v1"
DERIVED_ARTIFACT_RECORD_TYPE = "derived_artifact_registration"
SKELETON_PHASE12_DERIVED_ARTIFACT_V1 = "SKELETON_PHASE12_DERIVED_ARTIFACT_V1"
SKELETON_PHASE12_DERIVED_OUTPUT_V1 = "SKELETON_PHASE12_DERIVED_OUTPUT_V1"
SKELETON_PHASE12_DERIVED_BUILDER_V1 = "SKELETON_PHASE12_DERIVED_BUILDER_V1"
SKELETON_PHASE12_DERIVED_AUDIT_V1 = "SKELETON_PHASE12_DERIVED_AUDIT_V1"

NONE_SENTINEL = "none"
DIVERGENCE_CONTEXT_BYTES = 8

# Fixed comparison discipline mirroring memory_rebuild.COMPARISON_ORDER: the
# rebuilt payload bytes are compared first, then the recomputed output root;
# evaluation stops at the first mismatching stage.
DERIVED_COMPARISON_ORDER = ("artifact_bytes", "output_root")

_BUILDER_ID_PATTERN = re.compile(
    r"^skeleton\.[a-z0-9-]+(?:\.[a-z0-9-]+)*\.v[1-9][0-9]*$"
)
_MAX_BUILDER_ID_LENGTH = 128

DerivedArtifactBuilder = Callable[[Mapping[str, bytes]], bytes]
DerivedSourceProvider = Callable[[str], bytes]


class DerivedArtifactRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise DerivedArtifactRejection(code)


class DerivedVerificationStatus(StrEnum):
    """Closed per-artifact audit outcomes; a skip is not representable."""

    VERIFIED = "verified"
    DIVERGED = "diverged"
    UNREBUILDABLE = "unrebuildable"


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    frame = (
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return sha256(frame).hexdigest()


def compute_derived_output_root(artifact_bytes: bytes) -> str:
    """Content address of one derived-artifact payload under a fixed domain."""

    if type(artifact_bytes) is not bytes:
        _reject("derived_artifact_bytes_invalid")
    return _framed_digest(SKELETON_PHASE12_DERIVED_OUTPUT_V1, artifact_bytes)


def compute_derived_builder_code_sha256(builder_id: str) -> str:
    """Deterministic builder code identity bound to the closed builder id."""

    return _framed_digest(
        SKELETON_PHASE12_DERIVED_BUILDER_V1,
        builder_id.encode("utf-8", errors="strict"),
    )


@contextmanager
def _offline_environment() -> Iterator[None]:
    """The Phase 10 rebuild isolation idiom: no network, no ambient caches."""

    names = (
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONPYCACHEPREFIX",
        "PIP_CACHE_DIR",
        "XDG_CACHE_HOME",
        "HF_HOME",
        "TRANSFORMERS_CACHE",
        "TORCH_HOME",
    )
    prior = {name: os.environ.get(name) for name in names}
    prior_bytecode = sys.dont_write_bytecode
    original_socket = socket.socket
    original_connection = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo

    class _BlockedSocket(original_socket):
        def connect(self, *_args: object, **_kwargs: object) -> None:
            raise DerivedArtifactRejection("derived_network_access")

        def connect_ex(self, *_args: object, **_kwargs: object) -> int:
            raise DerivedArtifactRejection("derived_network_access")

    def blocked(*_args: object, **_kwargs: object) -> object:
        raise DerivedArtifactRejection("derived_network_access")

    try:
        for name in names:
            os.environ.pop(name, None)
        sys.dont_write_bytecode = True
        socket.socket = _BlockedSocket
        socket.create_connection = blocked
        socket.getaddrinfo = blocked
        yield
    finally:
        socket.socket = original_socket
        socket.create_connection = original_connection
        socket.getaddrinfo = original_getaddrinfo
        sys.dont_write_bytecode = prior_bytecode
        for name, value in prior.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


_REGISTRATION_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class DerivedArtifactRegistration:
    """One frozen schema-valid content-addressed registration document."""

    derived_artifact_id: str
    artifact_class: DerivedArtifactKind
    builder_id: str
    builder_version: str
    builder_code_sha256: str
    source_root_ids: tuple[str, ...]
    output_root: str
    authority_input: bool
    rebuildable: bool
    canonical_bytes: bytes
    canonical_sha256: str
    value: Mapping[str, Any]

    def __init__(
        self,
        *,
        derived_artifact_id: str,
        artifact_class: DerivedArtifactKind,
        builder_id: str,
        builder_code_sha256: str,
        source_root_ids: tuple[str, ...],
        output_root: str,
        canonical_bytes: bytes,
        value: Mapping[str, Any],
        token: object,
    ) -> None:
        if token is not _REGISTRATION_TOKEN:
            raise TypeError(
                "DerivedArtifactRegistration requires registry construction"
            )
        object.__setattr__(self, "derived_artifact_id", derived_artifact_id)
        object.__setattr__(self, "artifact_class", artifact_class)
        object.__setattr__(self, "builder_id", builder_id)
        object.__setattr__(self, "builder_version", builder_id)
        object.__setattr__(self, "builder_code_sha256", builder_code_sha256)
        object.__setattr__(self, "source_root_ids", tuple(source_root_ids))
        object.__setattr__(self, "output_root", output_root)
        object.__setattr__(self, "authority_input", False)
        object.__setattr__(self, "rebuildable", True)
        object.__setattr__(self, "canonical_bytes", bytes(canonical_bytes))
        object.__setattr__(self, "canonical_sha256", sha256(canonical_bytes).hexdigest())
        object.__setattr__(
            self,
            "value",
            MappingProxyType({key: item for key, item in value.items()}),
        )


@dataclass(frozen=True, slots=True)
class DerivedArtifactDivergence:
    """The exact first divergence: safe identities, offset, bounded context."""

    derived_artifact_id: str
    artifact_class: str
    divergence_stage: str
    byte_offset: int
    expected_length: int
    observed_length: int
    context_start: int
    expected_context_hex: str
    observed_context_hex: str
    expected_root: str
    observed_root: str

    def jsonable(self) -> dict[str, Any]:
        return {
            "derived_artifact_id": self.derived_artifact_id,
            "artifact_class": self.artifact_class,
            "divergence_stage": self.divergence_stage,
            "byte_offset": self.byte_offset,
            "expected_length": self.expected_length,
            "observed_length": self.observed_length,
            "context_start": self.context_start,
            "expected_context_hex": self.expected_context_hex,
            "observed_context_hex": self.observed_context_hex,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
        }


@dataclass(frozen=True, slots=True)
class DerivedRebuildOutcome:
    """One typed per-artifact verification outcome; never a skip."""

    derived_artifact_id: str
    artifact_class: str
    status: DerivedVerificationStatus
    rejection_code: str | None
    divergence: DerivedArtifactDivergence | None
    rebuilt_output_root: str

    def jsonable(self) -> dict[str, Any]:
        return {
            "derived_artifact_id": self.derived_artifact_id,
            "artifact_class": self.artifact_class,
            "status": str(self.status),
            "rejection_code": (
                NONE_SENTINEL if self.rejection_code is None else self.rejection_code
            ),
            "divergence": (
                NONE_SENTINEL if self.divergence is None else self.divergence.jsonable()
            ),
            "rebuilt_output_root": self.rebuilt_output_root,
        }


@dataclass(frozen=True, slots=True)
class DerivedArtifactAuditReport:
    """Deterministic digest-ordered audit sweep report."""

    total_count: int
    verified_count: int
    diverged_count: int
    unrebuildable_count: int
    outcomes: tuple[DerivedRebuildOutcome, ...]
    report_root: str

    def jsonable(self) -> dict[str, Any]:
        return {
            "total_count": self.total_count,
            "verified_count": self.verified_count,
            "diverged_count": self.diverged_count,
            "unrebuildable_count": self.unrebuildable_count,
            "outcomes": [outcome.jsonable() for outcome in self.outcomes],
            "report_root": self.report_root,
        }


def _first_byte_divergence(expected: bytes, observed: bytes) -> int | None:
    limit = min(len(expected), len(observed))
    for offset in range(limit):
        if expected[offset] != observed[offset]:
            return offset
    if len(expected) != len(observed):
        return limit
    return None


def _context_window(payload: bytes, offset: int) -> tuple[int, str]:
    start = max(0, offset - DIVERGENCE_CONTEXT_BYTES)
    stop = min(len(payload), offset + DIVERGENCE_CONTEXT_BYTES + 1)
    return start, payload[start:stop].hex()


class DerivedArtifactRegistry:
    """Closed builder registry plus schema-valid derived-artifact registrations.

    The registry exposes no payload accessor: registered payload bytes are
    reachable only through the isolated rebuild comparison, never returned to
    retrieval, gate, disposition, or retention callers.
    """

    __slots__ = (
        "_builders",
        "_surface",
        "_cycle_ordinal",
        "_cycle_input_root",
        "_fence_id",
        "_generation",
        "_attempt_ordinal",
        "_registrations",
        "_payloads",
    )

    def __init__(
        self,
        *,
        builders: Mapping[str, DerivedArtifactBuilder],
        surface: object | None = None,
        cycle_ordinal: int = 0,
        cycle_input_root: str | None = None,
        fence_id: str | None = None,
        generation: int = 0,
        attempt_ordinal: int = 1,
    ) -> None:
        if not isinstance(builders, Mapping) or not builders:
            _reject("derived_builder_registry_invalid")
        frozen: dict[str, DerivedArtifactBuilder] = {}
        for builder_id in sorted(builders):
            builder = builders[builder_id]
            if (
                not isinstance(builder_id, str)
                or len(builder_id) > _MAX_BUILDER_ID_LENGTH
                or _BUILDER_ID_PATTERN.fullmatch(builder_id) is None
                or not callable(builder)
            ):
                _reject("derived_builder_registry_invalid")
            frozen[builder_id] = builder
        if surface is not None and not callable(
            getattr(surface, "validate_derived_artifact", None)
        ):
            _reject("derived_contract_surface_invalid")
        if cycle_input_root is None:
            cycle_input_root = _framed_digest(
                SKELETON_PHASE12_DERIVED_ARTIFACT_V1 + ":cycle-input", b""
            )
        if fence_id is None:
            fence_id = _framed_digest(
                SKELETON_PHASE12_DERIVED_ARTIFACT_V1 + ":fence", b""
            )
        for identity in (cycle_input_root, fence_id):
            if not _is_sha256(identity):
                _reject("derived_cycle_context_invalid")
        for ordinal in (cycle_ordinal, generation):
            if type(ordinal) is not int or not 0 <= ordinal <= SAFE_INTEGER_MAX:
                _reject("derived_cycle_context_invalid")
        if type(attempt_ordinal) is not int or not 1 <= attempt_ordinal <= SAFE_INTEGER_MAX:
            _reject("derived_cycle_context_invalid")
        self._builders: Mapping[str, DerivedArtifactBuilder] = MappingProxyType(frozen)
        self._surface = surface
        self._cycle_ordinal = cycle_ordinal
        self._cycle_input_root = cycle_input_root
        self._fence_id = fence_id
        self._generation = generation
        self._attempt_ordinal = attempt_ordinal
        self._registrations: dict[str, DerivedArtifactRegistration] = {}
        self._payloads: dict[str, bytes] = {}

    @property
    def builder_ids(self) -> tuple[str, ...]:
        return tuple(self._builders)

    def registrations(self) -> tuple[DerivedArtifactRegistration, ...]:
        """Every registration in deterministic sorted-identity order."""

        return tuple(
            self._registrations[identity] for identity in sorted(self._registrations)
        )

    def registered_identities(self) -> frozenset[str]:
        """Registered artifact identities and output roots (MEM-19 boundary)."""

        identities: set[str] = set(self._registrations)
        identities.update(
            registration.output_root for registration in self._registrations.values()
        )
        return frozenset(identities)

    def register(
        self,
        artifact_kind: DerivedArtifactKind | str,
        source_roots: Iterable[str],
        builder_id: str,
        artifact_bytes: bytes,
    ) -> DerivedArtifactRegistration:
        """Produce one schema-valid content-addressed registration.

        Unsorted or duplicated source roots are tolerated and canonicalized
        to the sorted unique inventory; empty sources, unknown kinds, and
        unknown builders reject with typed codes.
        """

        try:
            kind = DerivedArtifactKind(artifact_kind)
        except (TypeError, ValueError) as error:
            raise DerivedArtifactRejection("derived_artifact_kind_unknown") from error
        if builder_id not in self._builders:
            _reject("derived_builder_unknown")
        if isinstance(source_roots, (str, bytes)) or not isinstance(
            source_roots, Iterable
        ):
            _reject("derived_source_roots_invalid")
        collected = tuple(source_roots)
        for root in collected:
            if not _is_sha256(root):
                _reject("derived_source_root_invalid")
        canonical_roots = tuple(sorted(set(collected)))
        if not canonical_roots:
            _reject("derived_source_roots_empty")
        if type(artifact_bytes) is not bytes:
            _reject("derived_artifact_bytes_invalid")

        value: dict[str, Any] = {
            "schema_version": DERIVED_ARTIFACT_SCHEMA_VERSION,
            "record_type": DERIVED_ARTIFACT_RECORD_TYPE,
            "cycle_ordinal": self._cycle_ordinal,
            "cycle_input_root": self._cycle_input_root,
            "fence_id": self._fence_id,
            "generation": self._generation,
            "attempt_ordinal": self._attempt_ordinal,
            "artifact_class": str(kind),
            "builder_version": builder_id,
            "builder_code_sha256": compute_derived_builder_code_sha256(builder_id),
            "source_root_ids": list(canonical_roots),
            "output_root": compute_derived_output_root(artifact_bytes),
            "authority_input": False,
            "rebuildable": True,
        }
        value["derived_artifact_id"] = compute_phase12_identity(
            SKELETON_PHASE12_DERIVED_ARTIFACT_V1, "derived_artifact_id", value
        )
        raw = canonicalize(value)
        if self._surface is not None:
            try:
                document = self._surface.validate_derived_artifact(raw)
            except DerivedArtifactRejection:
                raise
            except Exception as error:
                code = getattr(error, "code", "derived_registration_schema_invalid")
                raise DerivedArtifactRejection(str(code)) from error
            if document.identity != value["derived_artifact_id"]:
                _reject("derived_registration_identity_mismatch")

        identity = str(value["derived_artifact_id"])
        existing = self._registrations.get(identity)
        if existing is not None:
            # Identical content re-registration is idempotent by construction:
            # the identity binds every field including the output root.
            return existing
        registration = DerivedArtifactRegistration(
            derived_artifact_id=identity,
            artifact_class=kind,
            builder_id=builder_id,
            builder_code_sha256=str(value["builder_code_sha256"]),
            source_root_ids=canonical_roots,
            output_root=str(value["output_root"]),
            canonical_bytes=raw,
            value=value,
            token=_REGISTRATION_TOKEN,
        )
        self._registrations[identity] = registration
        self._payloads[identity] = bytes(artifact_bytes)
        return registration

    def _known_registration(
        self, registration: object
    ) -> DerivedArtifactRegistration:
        if not isinstance(registration, DerivedArtifactRegistration):
            _reject("derived_registration_invalid")
        known = self._registrations.get(registration.derived_artifact_id)
        if known is None or known.canonical_bytes != registration.canonical_bytes:
            _reject("derived_registration_unknown")
        return known

    def rebuild_and_verify(
        self,
        registration: DerivedArtifactRegistration,
        source_provider: DerivedSourceProvider,
        *,
        artifact_bytes: bytes | None = None,
    ) -> DerivedRebuildOutcome:
        """Re-run the registered builder in isolation and compare exactly.

        ``source_provider`` must return canonical bytes for every registered
        source root; a missing root, non-bytes source, unknown builder, or
        failing builder rejects with a typed code -- never a silent skip.
        The first mismatching byte terminates comparison with an exact
        divergence record carrying the offset and a bounded context window.
        """

        known = self._known_registration(registration)
        if not callable(source_provider):
            _reject("derived_source_provider_invalid")
        if artifact_bytes is None:
            expected = self._payloads[known.derived_artifact_id]
        else:
            if type(artifact_bytes) is not bytes:
                _reject("derived_artifact_bytes_invalid")
            expected = artifact_bytes
        builder = self._builders.get(known.builder_id)
        if builder is None:
            _reject("derived_builder_unknown")

        sources: dict[str, bytes] = {}
        with _offline_environment():
            for root in known.source_root_ids:
                try:
                    payload = source_provider(root)
                except DerivedArtifactRejection:
                    raise
                except Exception as error:
                    raise DerivedArtifactRejection(
                        "derived_source_root_missing"
                    ) from error
                if type(payload) is not bytes:
                    _reject("derived_source_bytes_invalid")
                sources[root] = payload
            try:
                rebuilt = builder(MappingProxyType(sources))
            except DerivedArtifactRejection:
                raise
            except Exception as error:
                raise DerivedArtifactRejection(
                    "derived_builder_execution_failed"
                ) from error
        if type(rebuilt) is not bytes:
            _reject("derived_builder_output_invalid")

        rebuilt_root = compute_derived_output_root(rebuilt)
        expected_root = compute_derived_output_root(expected)
        for stage in DERIVED_COMPARISON_ORDER:
            if stage == "artifact_bytes":
                offset = _first_byte_divergence(expected, rebuilt)
                if offset is None:
                    continue
                context_start, expected_context = _context_window(expected, offset)
                _, observed_context = _context_window(rebuilt, offset)
                divergence = DerivedArtifactDivergence(
                    derived_artifact_id=known.derived_artifact_id,
                    artifact_class=str(known.artifact_class),
                    divergence_stage=stage,
                    byte_offset=offset,
                    expected_length=len(expected),
                    observed_length=len(rebuilt),
                    context_start=context_start,
                    expected_context_hex=expected_context,
                    observed_context_hex=observed_context,
                    expected_root=expected_root,
                    observed_root=rebuilt_root,
                )
                return DerivedRebuildOutcome(
                    derived_artifact_id=known.derived_artifact_id,
                    artifact_class=str(known.artifact_class),
                    status=DerivedVerificationStatus.DIVERGED,
                    rejection_code=None,
                    divergence=divergence,
                    rebuilt_output_root=rebuilt_root,
                )
            if stage == "output_root" and rebuilt_root != known.output_root:
                divergence = DerivedArtifactDivergence(
                    derived_artifact_id=known.derived_artifact_id,
                    artifact_class=str(known.artifact_class),
                    divergence_stage=stage,
                    byte_offset=0,
                    expected_length=len(expected),
                    observed_length=len(rebuilt),
                    context_start=0,
                    expected_context_hex="",
                    observed_context_hex="",
                    expected_root=known.output_root,
                    observed_root=rebuilt_root,
                )
                return DerivedRebuildOutcome(
                    derived_artifact_id=known.derived_artifact_id,
                    artifact_class=str(known.artifact_class),
                    status=DerivedVerificationStatus.DIVERGED,
                    rejection_code=None,
                    divergence=divergence,
                    rebuilt_output_root=rebuilt_root,
                )
        return DerivedRebuildOutcome(
            derived_artifact_id=known.derived_artifact_id,
            artifact_class=str(known.artifact_class),
            status=DerivedVerificationStatus.VERIFIED,
            rejection_code=None,
            divergence=None,
            rebuilt_output_root=rebuilt_root,
        )

    def verify_all(
        self,
        registrations: Iterable[DerivedArtifactRegistration],
        source_provider: DerivedSourceProvider,
    ) -> DerivedArtifactAuditReport:
        """Audit every supplied registration in digest order, never skipping.

        A registration whose rebuild rejects (missing source root, failing
        builder, network attempt) is a typed ``unrebuildable`` outcome; the
        report is deterministic under any permutation of the input order.
        """

        if isinstance(registrations, (str, bytes)) or not isinstance(
            registrations, Iterable
        ):
            _reject("derived_registration_inventory_invalid")
        by_identity: dict[str, DerivedArtifactRegistration] = {}
        for registration in registrations:
            known = self._known_registration(registration)
            by_identity[known.derived_artifact_id] = known
        outcomes: list[DerivedRebuildOutcome] = []
        counts = {status: 0 for status in DerivedVerificationStatus}
        for identity in sorted(by_identity):
            known = by_identity[identity]
            try:
                outcome = self.rebuild_and_verify(known, source_provider)
            except DerivedArtifactRejection as error:
                outcome = DerivedRebuildOutcome(
                    derived_artifact_id=identity,
                    artifact_class=str(known.artifact_class),
                    status=DerivedVerificationStatus.UNREBUILDABLE,
                    rejection_code=error.code,
                    divergence=None,
                    rebuilt_output_root=GENESIS_SHA256,
                )
            counts[outcome.status] += 1
            outcomes.append(outcome)
        report_root = _framed_digest(
            SKELETON_PHASE12_DERIVED_AUDIT_V1,
            canonicalize([outcome.jsonable() for outcome in outcomes]),
        )
        return DerivedArtifactAuditReport(
            total_count=len(outcomes),
            verified_count=counts[DerivedVerificationStatus.VERIFIED],
            diverged_count=counts[DerivedVerificationStatus.DIVERGED],
            unrebuildable_count=counts[DerivedVerificationStatus.UNREBUILDABLE],
            outcomes=tuple(outcomes),
            report_root=report_root,
        )

    def assert_not_authority_input(self, document: Mapping[str, Any]) -> None:
        """MEM-19: no registered derived artifact may feed authority decisions.

        Rejects with a typed code if any registered derived-artifact identity
        or output root appears anywhere (keys or values, nested) inside the
        caller-supplied authority-relevant document.
        """

        if not isinstance(document, Mapping):
            _reject("derived_authority_document_invalid")
        forbidden = self.registered_identities()
        if not forbidden:
            return

        def _walk(value: object) -> None:
            if isinstance(value, str):
                if value in forbidden:
                    _reject("derived_artifact_authority_input_forbidden")
                return
            if isinstance(value, Mapping):
                for key, nested in value.items():
                    _walk(key)
                    _walk(nested)
                return
            if isinstance(value, (list, tuple)):
                for nested in value:
                    _walk(nested)

        _walk(document)


__all__ = [
    "DERIVED_ARTIFACT_RECORD_TYPE",
    "DERIVED_ARTIFACT_SCHEMA_VERSION",
    "DERIVED_COMPARISON_ORDER",
    "DIVERGENCE_CONTEXT_BYTES",
    "DerivedArtifactAuditReport",
    "DerivedArtifactBuilder",
    "DerivedArtifactDivergence",
    "DerivedArtifactRegistration",
    "DerivedArtifactRegistry",
    "DerivedArtifactRejection",
    "DerivedRebuildOutcome",
    "DerivedSourceProvider",
    "DerivedVerificationStatus",
    "SKELETON_PHASE12_DERIVED_ARTIFACT_V1",
    "SKELETON_PHASE12_DERIVED_AUDIT_V1",
    "SKELETON_PHASE12_DERIVED_BUILDER_V1",
    "SKELETON_PHASE12_DERIVED_OUTPUT_V1",
    "compute_derived_builder_code_sha256",
    "compute_derived_output_root",
]
