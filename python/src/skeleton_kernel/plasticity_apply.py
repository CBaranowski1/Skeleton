"""Two-phase atomic apply/rollback coordination for Phase 13 plasticity.

``ApplyCoordinator`` is the only path by which a parameter delta changes
application state.  It composes the sole-writer ``PlasticityStore`` (13-08)
with the pure fixed-point tensor kernel (13-07) and enforces:

Two-phase journaled apply
    Phase one appends a journaled intent — an append-only audit record
    carrying the delta id, the base tensor root, and the expected post root
    computed via the kernel BEFORE any application-state change.  Phase two
    appends the apply event only after the kernel proof triple validates
    byte-exactly (pre root, post root, and inverse round-trip reproducing
    the base payload bytes).  A crash between phases leaves only the
    journal intent; ``recover`` either completes phase two (re-proving from
    scratch) or terminally abandons with a typed ``apply_abandoned`` record
    — it never re-applies (the phase-two append is exactly-once by
    deterministic operation identity through the operation ledger) and
    never half-applies (rows are complete-or-absent).  This mirrors the
    Phase 12 release-publication journal discipline (staged intent ->
    commit marker -> recovery routine): the staged intent is the journal
    audit row, the commit marker is the ledger-guarded apply event itself,
    and ``recover`` is the recovery routine.

Byte-proof rollback
    A reverse event is appended only after applying the kernel inverse to
    the current post-state payload reproduces the pre-apply payload bytes
    exactly; any divergence rejects typed with first-divergence reporting
    and appends nothing.

Closed reversal cascade
    If delta B was applied on top of delta A (parent chain), reversing A
    directly rejects typed ``reversal_order_violation`` naming the exact
    blocking children; ``cascade_reverse`` computes the full ordered
    reversal plan deterministically (children before parents, siblings in
    delta-id order), validates every byte proof before appending anything,
    then appends the reverse events in order, each journal-guarded.

State reconstruction
    ``current_parameter_root`` folds apply/reverse events in global
    monotonic sequence order, recomputing every transition through the
    kernel and byte-proving each recorded root, over records returned by
    the store's ``replay_verify`` byte-identity surface.

Every timestamp is caller-provided canonical UTC text; this module never
reads a wall clock, never uses a float, and never iterates an unsorted
collection into a record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Callable, Mapping

from .canonical import canonicalize, parse_raw_json
from .plasticity_kernel import KERNEL_PAYLOAD_DOMAIN, tensor_payload_root
from .plasticity_store import (
    APPLY_EVENT,
    REVERSE_EVENT,
    AdmissionReceiptAppend,
    ApplicationPayloadProof,
    DeltaAppend,
    DeltaApplicationAppend,
    HomeostasisEventAppend,
    OperationReceipt,
    PlasticityStore,
    plasticity_record_identity,
)
from .plasticity_types import (
    GENESIS_SHA256,
    ParameterDelta,
    PlasticityTypeRejection,
    delta_from_raw,
)


APPLICATION_SCHEMA_VERSION = "skeleton.plasticity-application-event.v1"
INTENT_SCHEMA_VERSION = "skeleton.plasticity-apply-intent.v1"
ABANDONED_SCHEMA_VERSION = "skeleton.plasticity-apply-abandoned.v1"
APPLY_ABANDONED_CODE = "apply_abandoned"
PAYLOAD_DOMAIN = KERNEL_PAYLOAD_DOMAIN.encode("ascii")
_OPERATION_DOMAIN = b"SKELETON_PHASE13_APPLY_OPERATION_V1"
DIVERGENCE_CONTEXT_BYTES = 16
GLOBAL_SCOPE_SENTINEL = "global"
_JOURNAL_BUDGET_KIND = "application_frequency"
_JOURNAL_APPEND_CLASS = "audit_append"


class ApplyRejection(ValueError):
    """Typed fail-closed rejection carrying a closed snake_case code.

    ``blocking`` names the exact blocking delta identities for
    ``reversal_order_violation``; ``divergence`` carries first-divergence
    reporting (exact offset, bounded context, dual roots) for byte-proof
    failures.
    """

    def __init__(
        self,
        code: str,
        *,
        blocking: tuple[str, ...] = (),
        divergence: Mapping[str, object] | None = None,
    ) -> None:
        self.code = code
        self.blocking = tuple(blocking)
        self.divergence = None if divergence is None else dict(divergence)
        super().__init__(code)


def _reject(
    code: str,
    *,
    blocking: tuple[str, ...] = (),
    divergence: Mapping[str, object] | None = None,
) -> None:
    raise ApplyRejection(code, blocking=blocking, divergence=divergence)


def _framed_digest(domain: bytes, payload: bytes) -> str:
    return sha256(
        len(domain).to_bytes(8, "big")
        + domain
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def payload_root(payload: bytes) -> str:
    """The content-addressed root of one serialized tensor payload."""

    if not isinstance(payload, bytes):
        _reject("payload_bytes_invalid")
    return tensor_payload_root(payload)


def first_payload_divergence(
    expected: bytes, actual: bytes
) -> dict[str, object] | None:
    """Exact first-differing offset with bounded context and dual roots."""

    if expected == actual:
        return None
    limit = min(len(expected), len(actual))
    offset = limit
    for index in range(limit):
        if expected[index] != actual[index]:
            offset = index
            break
    start = max(0, offset - DIVERGENCE_CONTEXT_BYTES)
    stop = offset + DIVERGENCE_CONTEXT_BYTES
    return {
        "offset": offset,
        "expected_length": len(expected),
        "actual_length": len(actual),
        "expected_context_hex": expected[start:stop].hex(),
        "actual_context_hex": actual[start:stop].hex(),
        "expected_root": payload_root(expected),
        "actual_root": payload_root(actual),
    }


def _identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def delta_record_operation_id(delta_id: str) -> str:
    return _framed_digest(_OPERATION_DOMAIN, b"delta-record:" + delta_id.encode())


def intent_operation_id(application_id: str) -> str:
    return _framed_digest(_OPERATION_DOMAIN, b"intent:" + application_id.encode())


def event_operation_id(application_id: str) -> str:
    return _framed_digest(_OPERATION_DOMAIN, b"event:" + application_id.encode())


def cascade_operation_id(application_ids: tuple[str, ...]) -> str:
    if not application_ids:
        _reject("application_batch_invalid")
    return _framed_digest(
        _OPERATION_DOMAIN, b"cascade:" + canonicalize(list(application_ids))
    )


def abandon_operation_id(intent_event_id: str) -> str:
    return _framed_digest(_OPERATION_DOMAIN, b"abandon:" + intent_event_id.encode())


@dataclass(frozen=True, slots=True)
class _KernelSurface:
    """The two pure byte-level kernel operations the coordinator needs."""

    apply: Callable[[bytes, bytes], bytes]
    inverse: Callable[[bytes], bytes]


def _kernel_surface(kernel: object) -> _KernelSurface:
    if kernel is None:
        try:
            from . import plasticity_kernel as kernel_module
        except ImportError as error:
            raise ApplyRejection("plasticity_kernel_unavailable") from error
        kernel = kernel_module
    apply_bytes = getattr(kernel, "apply_delta_bytes", None)
    inverse_bytes = getattr(kernel, "inverse_delta_bytes", None)
    if callable(apply_bytes) and callable(inverse_bytes):
        return _KernelSurface(apply_bytes, inverse_bytes)
    apply_value = getattr(kernel, "apply_delta", None) or getattr(
        kernel, "apply", None
    )
    inverse_value = getattr(kernel, "inverse_delta", None) or getattr(
        kernel, "inverse", None
    )
    from_bytes = getattr(kernel, "payload_from_bytes", None)
    to_bytes = getattr(kernel, "payload_to_bytes", None)
    if (
        callable(apply_value)
        and callable(inverse_value)
        and callable(from_bytes)
        and callable(to_bytes)
    ):
        def apply_adapter(base: bytes, delta: bytes) -> bytes:
            return to_bytes(apply_value(from_bytes(base), from_bytes(delta)))

        def inverse_adapter(delta: bytes) -> bytes:
            return to_bytes(inverse_value(from_bytes(delta)))

        return _KernelSurface(apply_adapter, inverse_adapter)
    tensor_type = getattr(kernel, "TensorPayload", None) or getattr(
        kernel, "FixedPointTensor", None
    )
    if (
        callable(apply_value)
        and callable(inverse_value)
        and tensor_type is not None
        and callable(getattr(tensor_type, "from_elements", None))
    ):
        # The 13-07 reference kernel: pure tensor values with the frozen
        # length-framed big-endian canonical payload encoding
        # (scale_log2, shape frame, element frame).
        def decode(payload: bytes) -> object:
            if not isinstance(payload, bytes) or len(payload) < 24:
                _reject("payload_bytes_invalid")
            scale = int.from_bytes(payload[0:8], "big")
            dimension_count = int.from_bytes(payload[8:16], "big")
            offset = 16
            if len(payload) < offset + 8 * dimension_count + 8:
                _reject("payload_bytes_invalid")
            shape = tuple(
                int.from_bytes(payload[offset + 8 * index : offset + 8 * index + 8], "big")
                for index in range(dimension_count)
            )
            offset += 8 * dimension_count
            element_count = int.from_bytes(payload[offset : offset + 8], "big")
            offset += 8
            if len(payload) != offset + 8 * element_count:
                _reject("payload_bytes_invalid")
            elements = tuple(
                int.from_bytes(
                    payload[offset + 8 * index : offset + 8 * index + 8],
                    "big",
                    signed=True,
                )
                for index in range(element_count)
            )
            return tensor_type.from_elements(shape, elements, scale)

        def encode(tensor: object) -> bytes:
            return tensor.canonical_payload_bytes()

        def apply_tensor_adapter(base: bytes, delta: bytes) -> bytes:
            return encode(apply_value(decode(base), decode(delta)))

        def inverse_tensor_adapter(delta: bytes) -> bytes:
            return encode(inverse_value(decode(delta)))

        return _KernelSurface(apply_tensor_adapter, inverse_tensor_adapter)
    raise ApplyRejection("plasticity_kernel_interface_invalid")


@dataclass(frozen=True, slots=True)
class ApplicationEvent:
    """One parsed coordinator-authored delta-application event document."""

    application_id: str
    delta_id: str
    application_event: str
    application_ordinal: int
    state_sequence: int
    scope_key: str
    base_payload_root: str
    result_payload_root: str
    tensor_payload_root: str
    inverse_payload_root: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ApplyIntent:
    """One parsed journaled intent record awaiting resolution."""

    intent_event_id: str
    application_id: str
    delta_id: str
    application_event: str
    application_ordinal: int
    state_sequence: int
    scope_key: str
    base_payload_root: str
    result_payload_root: str
    tensor_payload_root: str
    inverse_payload_root: str


@dataclass(frozen=True, slots=True)
class ApplyReceipt:
    """The typed result of one committed apply or reverse event."""

    application_id: str
    delta_id: str
    application_event: str
    application_ordinal: int
    state_sequence: int
    base_payload_root: str
    result_payload_root: str
    receipt: OperationReceipt


@dataclass(frozen=True, slots=True)
class AdmissionEvidence:
    """Independent gate facts bound into the sole activation receipt."""

    provider_snapshot_id: str
    evidence_gradient_ids: tuple[str, ...]
    channel_update_id: str
    ordered_probe_receipt_ids: tuple[str, ...]
    probe_battery_root: str
    scope_id: str
    current_ordinal: int
    provider_activation_evidence: object | None = None
    admitted: bool = True


@dataclass(frozen=True, slots=True)
class RecoveryOutcome:
    """The typed disposition of one journaled intent during recovery."""

    intent_event_id: str
    delta_id: str
    application_event: str
    application_ordinal: int
    disposition: str
    code: str
    cause: str


@dataclass(frozen=True, slots=True)
class _LedgerView:
    deltas: Mapping[str, ParameterDelta]
    events: tuple[ApplicationEvent, ...]
    intents: tuple[ApplyIntent, ...]
    abandoned_intent_ids: frozenset[str]
    children: Mapping[str, tuple[str, ...]]
    next_sequence: int

    def committed_application_ids(self) -> frozenset[str]:
        return frozenset(event.application_id for event in self.events)


_APPLICATION_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "delta_id",
        "application_event",
        "application_ordinal",
        "state_sequence",
        "scope_key",
        "base_payload_root",
        "result_payload_root",
        "tensor_payload_root",
        "inverse_payload_root",
    }
)
_INTENT_FIELDS = frozenset({*_APPLICATION_FIELDS, "application_id"})


def _application_document(
    *,
    delta_id: str,
    application_event: str,
    application_ordinal: int,
    state_sequence: int,
    scope_key: str,
    base_payload_root: str,
    result_payload_root: str,
    tensor_payload_root: str,
    inverse_payload_root: str,
) -> dict[str, object]:
    return {
        "schema_version": APPLICATION_SCHEMA_VERSION,
        "record_type": "delta_application_event",
        "delta_id": delta_id,
        "application_event": application_event,
        "application_ordinal": application_ordinal,
        "state_sequence": state_sequence,
        "scope_key": scope_key,
        "base_payload_root": base_payload_root,
        "result_payload_root": result_payload_root,
        "tensor_payload_root": tensor_payload_root,
        "inverse_payload_root": inverse_payload_root,
    }


def _application_event_from_document(
    value: Mapping[str, Any], raw: bytes
) -> ApplicationEvent:
    if set(value) != _APPLICATION_FIELDS:
        _reject("application_record_invalid")
    if value.get("record_type") != "delta_application_event":
        _reject("application_record_invalid")
    event = value["application_event"]
    if event not in (APPLY_EVENT, REVERSE_EVENT):
        _reject("application_record_invalid")
    ordinal = value["application_ordinal"]
    sequence = value["state_sequence"]
    if type(ordinal) is not int or ordinal < 1:
        _reject("application_record_invalid")
    if type(sequence) is not int or sequence < 1:
        _reject("application_record_invalid")
    scope_key = value["scope_key"]
    if not isinstance(scope_key, str) or not scope_key:
        _reject("application_record_invalid")
    return ApplicationEvent(
        application_id=plasticity_record_identity("delta_application", raw),
        delta_id=_identity(value["delta_id"], "application_record_invalid"),
        application_event=str(event),
        application_ordinal=ordinal,
        state_sequence=sequence,
        scope_key=str(scope_key),
        base_payload_root=_identity(
            value["base_payload_root"], "application_record_invalid"
        ),
        result_payload_root=_identity(
            value["result_payload_root"], "application_record_invalid"
        ),
        tensor_payload_root=_identity(
            value["tensor_payload_root"], "application_record_invalid"
        ),
        inverse_payload_root=_identity(
            value["inverse_payload_root"], "application_record_invalid"
        ),
        canonical_bytes=raw,
    )


def _intent_from_document(value: Mapping[str, Any], raw: bytes) -> ApplyIntent:
    if set(value) != _INTENT_FIELDS:
        _reject("apply_intent_invalid")
    if value.get("record_type") != "plasticity_apply_intent":
        _reject("apply_intent_invalid")
    event = value["application_event"]
    if event not in (APPLY_EVENT, REVERSE_EVENT):
        _reject("apply_intent_invalid")
    ordinal = value["application_ordinal"]
    sequence = value["state_sequence"]
    if type(ordinal) is not int or ordinal < 1:
        _reject("apply_intent_invalid")
    if type(sequence) is not int or sequence < 1:
        _reject("apply_intent_invalid")
    scope_key = value["scope_key"]
    if not isinstance(scope_key, str) or not scope_key:
        _reject("apply_intent_invalid")
    return ApplyIntent(
        intent_event_id=plasticity_record_identity("homeostasis_event", raw),
        application_id=_identity(value["application_id"], "apply_intent_invalid"),
        delta_id=_identity(value["delta_id"], "apply_intent_invalid"),
        application_event=str(event),
        application_ordinal=ordinal,
        state_sequence=sequence,
        scope_key=str(scope_key),
        base_payload_root=_identity(
            value["base_payload_root"], "apply_intent_invalid"
        ),
        result_payload_root=_identity(
            value["result_payload_root"], "apply_intent_invalid"
        ),
        tensor_payload_root=_identity(
            value["tensor_payload_root"], "apply_intent_invalid"
        ),
        inverse_payload_root=_identity(
            value["inverse_payload_root"], "apply_intent_invalid"
        ),
    )


@dataclass(frozen=True, slots=True)
class _ReversalStep:
    delta: ParameterDelta
    application_ordinal: int
    base_payload_root: str
    result_payload_root: str
    proof: ApplicationPayloadProof


def canonical_scope_key(scope_kind: str, project_id: str | None = None) -> str:
    """Return the stable namespace key used by every apply-state chain."""

    if not isinstance(scope_kind, str) or not scope_kind:
        _reject("apply_scope_base_invalid")
    if scope_kind == "project":
        return f"project:{_identity(project_id, 'apply_scope_base_invalid')}"
    if project_id is not None:
        _reject("apply_scope_base_invalid")
    return scope_kind


def _delta_scope_key(delta: ParameterDelta) -> str:
    return canonical_scope_key(delta.scope_kind.value, delta.project_id)


class ApplyCoordinator:
    """Two-phase journaled apply/rollback over the store and kernel.

    ``payload_resolver`` maps a content root to exact serialized payload
    bytes (the scope base payload and every delta tensor payload); the
    coordinator re-proves every resolved payload's root before trusting a
    byte of it.  ``fault_hook`` is the test-owned crash-injection seam: it
    is invoked with a stage name at each phase boundary and may raise to
    simulate a crash at that exact window.
    """

    __slots__ = (
        "_store",
        "_kernel",
        "_writer_id",
        "_fence_id",
        "_generation",
        "_recorded_at",
        "_scope_base_roots",
        "_payload_resolver",
        "_fault_hook",
        "_admission_resolver",
        "_commit_capability",
    )

    def __init__(
        self,
        store: PlasticityStore,
        *,
        kernel: object | None = None,
        writer_id: str,
        fence_id: str,
        generation: int,
        recorded_at: str,
        scope_base_roots: Mapping[str, str],
        payload_resolver: Callable[[str], bytes | None],
        admission_resolver: Callable[[ParameterDelta], AdmissionEvidence],
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(store, PlasticityStore):
            _reject("apply_store_invalid")
        self._store = store
        self._kernel = _kernel_surface(kernel)
        self._writer_id = _identity(writer_id, "apply_writer_invalid")
        self._fence_id = _identity(fence_id, "apply_fence_invalid")
        if type(generation) is not int or generation < 0:
            _reject("apply_fence_invalid")
        self._generation = generation
        if not isinstance(recorded_at, str) or not recorded_at.endswith("Z"):
            _reject("apply_recorded_at_invalid")
        self._recorded_at = recorded_at
        if not isinstance(scope_base_roots, Mapping):
            _reject("apply_scope_base_invalid")
        bases = {}
        for scope_kind in sorted(str(key) for key in scope_base_roots):
            bases[scope_kind] = _identity(
                scope_base_roots[scope_kind], "apply_scope_base_invalid"
            )
        self._scope_base_roots = bases
        if not callable(payload_resolver):
            _reject("apply_payload_resolver_invalid")
        self._payload_resolver = payload_resolver
        if not callable(admission_resolver):
            _reject("admission_resolver_invalid")
        self._admission_resolver = admission_resolver
        if fault_hook is not None and not callable(fault_hook):
            _reject("apply_fault_hook_invalid")
        self._fault_hook = fault_hook
        self._commit_capability = store._issue_application_commit_capability(
            writer_id=self._writer_id,
            fence_id=self._fence_id,
            generation=self._generation,
        )

    # -- pure helpers -----------------------------------------------------

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def _resolve(self, root: str) -> bytes:
        root = _identity(root, "payload_root_invalid")
        try:
            payload = self._payload_resolver(root)
        except ApplyRejection:
            raise
        except Exception as error:
            raise ApplyRejection("payload_unavailable") from error
        if payload is None:
            _reject("payload_unavailable")
        if not isinstance(payload, bytes):
            _reject("payload_bytes_invalid")
        if payload_root(payload) != root:
            _reject("payload_root_mismatch")
        return payload

    @staticmethod
    def _kernel_code(error: Exception) -> str:
        code = getattr(error, "code", None)
        return code if isinstance(code, str) and code else "plasticity_kernel_failure"

    def _kernel_apply(self, base: bytes, delta: bytes) -> bytes:
        try:
            result = self._kernel.apply(base, delta)
        except ApplyRejection:
            raise
        except Exception as error:
            raise ApplyRejection(self._kernel_code(error)) from error
        if not isinstance(result, bytes):
            _reject("plasticity_kernel_interface_invalid")
        return result

    def _kernel_inverse(self, delta: bytes) -> bytes:
        try:
            result = self._kernel.inverse(delta)
        except ApplyRejection:
            raise
        except Exception as error:
            raise ApplyRejection(self._kernel_code(error)) from error
        if not isinstance(result, bytes):
            _reject("plasticity_kernel_interface_invalid")
        return result

    # -- ledger view ------------------------------------------------------

    def _snapshot(self) -> _LedgerView:
        replay = self._store.replay_verify()
        deltas: dict[str, ParameterDelta] = {}
        events: list[ApplicationEvent] = []
        intents: list[ApplyIntent] = []
        abandoned: set[str] = set()
        for table, _record_id, _digest, raw in replay.records:
            if table == "parameter_deltas":
                try:
                    delta = delta_from_raw(raw)
                except PlasticityTypeRejection as error:
                    raise ApplyRejection(error.code) from error
                deltas[delta.delta_id] = delta
            elif table == "delta_applications":
                value = parse_raw_json(raw)
                if (
                    isinstance(value, Mapping)
                    and value.get("schema_version") == APPLICATION_SCHEMA_VERSION
                ):
                    events.append(_application_event_from_document(value, raw))
            elif table == "homeostasis_events":
                value = parse_raw_json(raw)
                if not isinstance(value, Mapping):
                    continue
                schema_version = value.get("schema_version")
                if schema_version == INTENT_SCHEMA_VERSION:
                    intents.append(_intent_from_document(value, raw))
                elif schema_version == ABANDONED_SCHEMA_VERSION:
                    intent_event_id = value.get("intent_event_id")
                    if intent_event_id is not None:
                        abandoned.add(
                            _identity(intent_event_id, "apply_intent_invalid")
                        )
        events.sort(key=lambda event: (event.state_sequence, event.application_id))
        sequences = [event.state_sequence for event in events]
        if len(set(sequences)) != len(sequences):
            _reject("state_sequence_duplicate")
        intents.sort(
            key=lambda intent: (intent.state_sequence, intent.intent_event_id)
        )
        children: dict[str, list[str]] = {}
        for delta_id in sorted(deltas):
            parent = deltas[delta_id].parent_delta_id
            if parent != GENESIS_SHA256:
                children.setdefault(parent, []).append(delta_id)
        return _LedgerView(
            deltas=deltas,
            events=tuple(events),
            intents=tuple(intents),
            abandoned_intent_ids=frozenset(abandoned),
            children={
                parent: tuple(sorted(names)) for parent, names in children.items()
            },
            next_sequence=(sequences[-1] + 1) if sequences else 1,
        )

    def _scope_base_root(self, scope_key: str) -> str:
        root = self._scope_base_roots.get(scope_key)
        if root is None:
            _reject("scope_base_unknown")
        return root

    def _fold(
        self, view: _LedgerView, scope_key: str, *, byte_prove: bool
    ) -> tuple[str, bytes | None]:
        """Fold the scope's events in sequence order to the current state.

        With ``byte_prove`` every transition is recomputed through the
        kernel and each recorded root is byte-proven; without it the fold
        follows the recorded root chain (each link was byte-proven at
        append time).
        """

        current_root = self._scope_base_root(scope_key)
        current_bytes = self._resolve(current_root) if byte_prove else None
        for event in view.events:
            if event.scope_key != scope_key:
                continue
            if event.base_payload_root != current_root:
                _reject("state_chain_divergent")
            if byte_prove:
                assert current_bytes is not None
                tensor = self._resolve(event.tensor_payload_root)
                if event.application_event == APPLY_EVENT:
                    computed = self._kernel_apply(current_bytes, tensor)
                else:
                    computed = self._kernel_apply(
                        current_bytes, self._kernel_inverse(tensor)
                    )
                if payload_root(computed) != event.result_payload_root:
                    _reject(
                        "state_chain_divergent",
                        divergence={
                            "expected_root": event.result_payload_root,
                            "actual_root": payload_root(computed),
                        },
                    )
                current_bytes = computed
            current_root = event.result_payload_root
        return current_root, current_bytes

    # -- appends ----------------------------------------------------------

    def _append_delta_record(self, delta: ParameterDelta) -> None:
        self._store.append_delta(
            DeltaAppend(
                delta.canonical_bytes,
                self._fence_id,
                self._generation,
                0,
                self._recorded_at,
            ),
            writer_id=self._writer_id,
            operation_id=delta_record_operation_id(delta.delta_id),
        )

    def _append_journal_event(self, raw: bytes, *, sequence: int, operation_id: str) -> str:
        event_id = plasticity_record_identity("homeostasis_event", raw)
        self._store.append_homeostasis_event(
            HomeostasisEventAppend(
                event_id,
                GLOBAL_SCOPE_SENTINEL,
                _JOURNAL_BUDGET_KIND,
                _JOURNAL_APPEND_CLASS,
                True,
                0,
                0,
                0,
                0,
                0,
                0,
                "nominal",
                "admit",
                sequence,
                self._fence_id,
                self._generation,
                sequence,
                self._recorded_at,
                raw,
            ),
            writer_id=self._writer_id,
            operation_id=operation_id,
        )
        return event_id

    def _append_intent(self, document: Mapping[str, object]) -> str:
        raw = canonicalize(dict(document))
        application_id = str(document["application_id"])
        return self._append_journal_event(
            raw,
            sequence=int(document["state_sequence"]),
            operation_id=intent_operation_id(application_id),
        )

    def _append_abandoned(self, intent: ApplyIntent, cause: str) -> None:
        raw = canonicalize(
            {
                "schema_version": ABANDONED_SCHEMA_VERSION,
                "record_type": "plasticity_apply_abandoned",
                "code": APPLY_ABANDONED_CODE,
                "cause_code": cause,
                "intent_event_id": intent.intent_event_id,
                "delta_id": intent.delta_id,
                "application_event": intent.application_event,
                "application_ordinal": intent.application_ordinal,
                "state_sequence": intent.state_sequence,
            }
        )
        self._append_journal_event(
            raw,
            sequence=intent.state_sequence,
            operation_id=abandon_operation_id(intent.intent_event_id),
        )

    def _append_event(
        self,
        document: Mapping[str, object],
        proof: ApplicationPayloadProof,
        admission: tuple[
            AdmissionReceiptAppend,
            tuple[HomeostasisEventAppend, ...],
            object,
        ]
        | None = None,
    ) -> tuple[str, OperationReceipt]:
        raw = canonicalize(
            {key: value for key, value in document.items() if key != "application_id"}
        )
        application_id = plasticity_record_identity("delta_application", raw)
        application = DeltaApplicationAppend(
                application_id,
                str(document["delta_id"]),
                str(document["application_event"]),
                int(document["application_ordinal"]),
                self._fence_id,
                self._generation,
                int(document["state_sequence"]),
                self._recorded_at,
                raw,
        )
        if document["application_event"] == APPLY_EVENT:
            if admission is None:
                _reject("application_admission_required")
            receipt = self._store._commit_admission_application(
                admission=admission[0],
                application=application,
                homeostasis=admission[1],
                provider_evidence=admission[2],
                proof=proof,
                capability=self._commit_capability,
                writer_id=self._writer_id,
                operation_id=event_operation_id(application_id),
            )
        else:
            receipt = self._store.append_delta_application(
                application,
                proof=proof,
                capability=self._commit_capability,
                writer_id=self._writer_id,
                operation_id=event_operation_id(application_id),
            )
        return application_id, receipt

    def _admit(
        self, delta: ParameterDelta, proof: ApplicationPayloadProof
    ) -> tuple[
        AdmissionReceiptAppend,
        tuple[HomeostasisEventAppend, ...],
        object,
    ]:
        try:
            evidence = self._admission_resolver(delta)
        except ApplyRejection:
            raise
        except Exception as error:
            raise ApplyRejection("admission_evidence_unavailable") from error
        if not isinstance(evidence, AdmissionEvidence) or evidence.admitted is not True:
            _reject("admission_denied")
        if type(evidence.current_ordinal) is not int or evidence.current_ordinal < 0:
            _reject("admission_evidence_invalid")
        if (
            evidence.provider_snapshot_id != delta.base_snapshot_id
            or evidence.evidence_gradient_ids != delta.evidence_gradient_ids
            or evidence.current_ordinal > delta.expiry_ordinal
            or len(evidence.ordered_probe_receipt_ids) != 5
            or len(set(evidence.ordered_probe_receipt_ids)) != 5
        ):
            _reject("admission_evidence_mismatch")
        provider_evidence = evidence.provider_activation_evidence
        authorize_live = getattr(
            provider_evidence, "_authorizes_live_activation", None
        )
        if not callable(authorize_live) or not authorize_live(
            base_snapshot_id=delta.base_snapshot_id,
            adapter_digest=delta.tensor_payload_root,
        ):
            _reject("provider_verified_load_required")
        try:
            provider_loaded_snapshot_id = provider_evidence.loaded_snapshot_id
            provider_verification_id = provider_evidence.verification_id
            provider_load_operation_id = provider_evidence.operation_id
            provider_authorization_sha256 = provider_evidence.authorization_sha256
            provider_lifecycle_receipt_ids = provider_evidence.lifecycle_receipt_ids
        except AttributeError as error:
            raise ApplyRejection("provider_verified_load_required") from error
        for identity in (
            evidence.channel_update_id,
            *evidence.ordered_probe_receipt_ids,
            evidence.probe_battery_root,
            evidence.scope_id,
            provider_loaded_snapshot_id,
            provider_verification_id,
            provider_load_operation_id,
            provider_authorization_sha256,
            *provider_lifecycle_receipt_ids,
        ):
            _identity(identity, "admission_evidence_invalid")
        homeostasis_window = self._snapshot().next_sequence
        homeostasis = self._store._prepare_homeostasis_admission(
            delta_id=delta.delta_id,
            scope_id=evidence.scope_id,
            window_ordinal=homeostasis_window,
            proof=proof,
            fence_id=self._fence_id,
            generation=self._generation,
            attempt_ordinal=homeostasis_window,
            recorded_at=self._recorded_at,
            writer_id=self._writer_id,
        )
        homeostasis_event_ids = tuple(item.event_id for item in homeostasis)
        homeostasis_set_root = self._store.homeostasis_set_root(
            homeostasis_event_ids
        )
        raw = canonicalize(
            {
                "schema_version": "skeleton.plasticity-admission.v1",
                "record_type": "plasticity_admission",
                "delta_id": delta.delta_id,
                "provider_snapshot_id": evidence.provider_snapshot_id,
                "provider_loaded_snapshot_id": provider_loaded_snapshot_id,
                "provider_verification_id": provider_verification_id,
                "provider_load_operation_id": provider_load_operation_id,
                "provider_authorization_sha256": provider_authorization_sha256,
                "provider_lifecycle_receipt_ids": list(
                    provider_lifecycle_receipt_ids
                ),
                "evidence_gradient_ids": list(evidence.evidence_gradient_ids),
                "channel_update_id": evidence.channel_update_id,
                "ordered_probe_receipt_ids": list(
                    evidence.ordered_probe_receipt_ids
                ),
                "probe_battery_root": evidence.probe_battery_root,
                "scope_id": evidence.scope_id,
                "expiry_ordinal": delta.expiry_ordinal,
                "current_ordinal": evidence.current_ordinal,
                "homeostasis_event_id": homeostasis_event_ids[0],
                "homeostasis_event_ids": list(homeostasis_event_ids),
                "homeostasis_set_root": homeostasis_set_root,
                "homeostasis_window_ordinal": homeostasis_window,
                "decision": "admitted",
            }
        )
        return (
            AdmissionReceiptAppend(
                plasticity_record_identity("admission", raw),
                delta.delta_id,
                evidence.provider_snapshot_id,
                evidence.channel_update_id,
                evidence.probe_battery_root,
                evidence.scope_id,
                delta.expiry_ordinal,
                evidence.current_ordinal,
                homeostasis_event_ids[0],
                raw,
            ),
            homeostasis,
            provider_evidence,
        )

    def _journal_and_commit(
        self,
        *,
        delta: ParameterDelta,
        application_event: str,
        application_ordinal: int,
        state_sequence: int,
        base_payload_root: str,
        result_payload_root: str,
        proof: ApplicationPayloadProof,
        admission: tuple[
            AdmissionReceiptAppend,
            tuple[HomeostasisEventAppend, ...],
            object,
        ]
        | None = None,
    ) -> ApplyReceipt:
        application = _application_document(
            delta_id=delta.delta_id,
            application_event=application_event,
            application_ordinal=application_ordinal,
            state_sequence=state_sequence,
            scope_key=_delta_scope_key(delta),
            base_payload_root=base_payload_root,
            result_payload_root=result_payload_root,
            tensor_payload_root=delta.tensor_payload_root,
            inverse_payload_root=delta.inverse_payload_root,
        )
        application_raw = canonicalize(dict(application))
        application_id = plasticity_record_identity(
            "delta_application", application_raw
        )
        intent = dict(application)
        intent["schema_version"] = INTENT_SCHEMA_VERSION
        intent["record_type"] = "plasticity_apply_intent"
        intent["application_id"] = application_id
        self._append_intent(intent)
        self._fault("between_phases")
        committed_id, receipt = self._append_event(application, proof, admission)
        self._fault("after_event")
        return ApplyReceipt(
            application_id=committed_id,
            delta_id=delta.delta_id,
            application_event=application_event,
            application_ordinal=application_ordinal,
            state_sequence=state_sequence,
            base_payload_root=base_payload_root,
            result_payload_root=result_payload_root,
            receipt=receipt,
        )

    def _commit_reversal_batch(
        self, steps: tuple[_ReversalStep, ...], *, first_sequence: int
    ) -> tuple[ApplyReceipt, ...]:
        intents: list[HomeostasisEventAppend] = []
        applications: list[DeltaApplicationAppend] = []
        proofs: list[ApplicationPayloadProof] = []
        products: list[tuple[str, _ReversalStep, int]] = []
        application_ids: list[str] = []
        for index, step in enumerate(steps):
            sequence = first_sequence + index
            document = _application_document(
                delta_id=step.delta.delta_id,
                application_event=REVERSE_EVENT,
                application_ordinal=step.application_ordinal,
                state_sequence=sequence,
                scope_key=_delta_scope_key(step.delta),
                base_payload_root=step.base_payload_root,
                result_payload_root=step.result_payload_root,
                tensor_payload_root=step.delta.tensor_payload_root,
                inverse_payload_root=step.delta.inverse_payload_root,
            )
            application_raw = canonicalize(dict(document))
            application_id = plasticity_record_identity(
                "delta_application", application_raw
            )
            intent_document = dict(document)
            intent_document["schema_version"] = INTENT_SCHEMA_VERSION
            intent_document["record_type"] = "plasticity_apply_intent"
            intent_document["application_id"] = application_id
            intent_raw = canonicalize(intent_document)
            intents.append(
                HomeostasisEventAppend(
                    plasticity_record_identity("homeostasis_event", intent_raw),
                    GLOBAL_SCOPE_SENTINEL,
                    _JOURNAL_BUDGET_KIND,
                    _JOURNAL_APPEND_CLASS,
                    True,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    "nominal",
                    "admit",
                    sequence,
                    self._fence_id,
                    self._generation,
                    sequence,
                    self._recorded_at,
                    intent_raw,
                )
            )
            applications.append(
                DeltaApplicationAppend(
                    application_id,
                    step.delta.delta_id,
                    REVERSE_EVENT,
                    step.application_ordinal,
                    self._fence_id,
                    self._generation,
                    sequence,
                    self._recorded_at,
                    application_raw,
                )
            )
            proofs.append(step.proof)
            application_ids.append(application_id)
            products.append((application_id, step, sequence))
            # The externally visible crash seam runs before the sole atomic
            # write. A failure at any planned row therefore leaves no prefix.
            self._fault("after_event")
            self._fault(f"cascade_after_event_{index}")
        receipt = self._store._append_application_batch(
            tuple(intents),
            tuple(applications),
            tuple(proofs),
            capability=self._commit_capability,
            writer_id=self._writer_id,
            operation_id=cascade_operation_id(tuple(application_ids)),
        )
        return tuple(
            ApplyReceipt(
                application_id=application_id,
                delta_id=step.delta.delta_id,
                application_event=REVERSE_EVENT,
                application_ordinal=step.application_ordinal,
                state_sequence=sequence,
                base_payload_root=step.base_payload_root,
                result_payload_root=step.result_payload_root,
                receipt=receipt,
            )
            for application_id, step, sequence in products
        )

    # -- proofs -----------------------------------------------------------

    def _prove_apply(
        self, delta: ParameterDelta, base: bytes
    ) -> tuple[bytes, bytes, bytes]:
        """The apply-time proof triple: post root, inverse root, roundtrip."""

        if payload_root(base) != delta.pre_apply_payload_root:
            _reject("base_root_divergent")
        tensor = self._resolve(delta.tensor_payload_root)
        post = self._kernel_apply(base, tensor)
        if payload_root(post) != delta.post_apply_payload_root:
            _reject(
                "apply_proof_post_root_mismatch",
                divergence={
                    "expected_root": delta.post_apply_payload_root,
                    "actual_root": payload_root(post),
                },
            )
        inverse = self._kernel_inverse(tensor)
        if payload_root(inverse) != delta.inverse_payload_root:
            _reject("inverse_payload_root_mismatch")
        roundtrip = self._kernel_apply(post, inverse)
        if roundtrip != base:
            _reject(
                "apply_proof_roundtrip_divergent",
                divergence=first_payload_divergence(base, roundtrip),
            )
        if payload_root(roundtrip) != delta.roundtrip_payload_root:
            _reject("apply_proof_roundtrip_divergent")
        return post, inverse, tensor

    def _prove_reverse(
        self, delta: ParameterDelta, current: bytes
    ) -> tuple[bytes, bytes, bytes]:
        """The reverse-time proof: post + inverse -> pre, byte-exact."""

        if payload_root(current) != delta.post_apply_payload_root:
            _reject("base_root_divergent")
        tensor = self._resolve(delta.tensor_payload_root)
        inverse = self._kernel_inverse(tensor)
        if payload_root(inverse) != delta.inverse_payload_root:
            _reject("inverse_payload_root_mismatch")
        recomputed = self._kernel_apply(current, inverse)
        if payload_root(recomputed) != delta.pre_apply_payload_root:
            try:
                expected = self._resolve(delta.pre_apply_payload_root)
            except ApplyRejection:
                expected = None
            divergence: Mapping[str, object] | None
            if expected is None:
                divergence = {
                    "expected_root": delta.pre_apply_payload_root,
                    "actual_root": payload_root(recomputed),
                }
            else:
                divergence = first_payload_divergence(expected, recomputed)
            _reject("reverse_proof_divergent", divergence=divergence)
        return recomputed, inverse, tensor

    def _authenticate(self, delta_raw: bytes) -> ParameterDelta:
        try:
            return delta_from_raw(delta_raw)
        except PlasticityTypeRejection as error:
            raise ApplyRejection(error.code) from error

    # -- public surface ---------------------------------------------------

    def apply(self, delta_raw: bytes) -> ApplyReceipt:
        """Two-phase journaled apply of one authenticated parameter delta."""

        delta = self._authenticate(delta_raw)
        view = self._snapshot()
        state = self._store.application_state(delta.delta_id)
        if state.state == "applied":
            _reject("delta_already_applied")
        if delta.parent_delta_id != GENESIS_SHA256:
            parent = view.deltas.get(delta.parent_delta_id)
            if parent is None:
                _reject("parent_delta_unknown")
            if _delta_scope_key(parent) != _delta_scope_key(delta):
                _reject("parent_scope_divergent")
            if parent.base_snapshot_id != delta.base_snapshot_id:
                _reject("parent_snapshot_divergent")
            if self._store.application_state(parent.delta_id).state != "applied":
                _reject("parent_not_applied")
        scope_key = _delta_scope_key(delta)
        chain_root, base = self._fold(view, scope_key, byte_prove=True)
        assert base is not None
        if chain_root != delta.pre_apply_payload_root:
            _reject("base_root_divergent")
        post, inverse, tensor = self._prove_apply(delta, base)
        self._append_delta_record(delta)
        proof = ApplicationPayloadProof(base, post, tensor, inverse)
        admission = self._admit(delta, proof)
        return self._journal_and_commit(
            delta=delta,
            application_event=APPLY_EVENT,
            application_ordinal=state.last_ordinal + 1,
            state_sequence=view.next_sequence,
            base_payload_root=delta.pre_apply_payload_root,
            result_payload_root=payload_root(post),
            proof=proof,
            admission=admission,
        )

    def _applied_descendants(
        self, view: _LedgerView, delta_id: str
    ) -> tuple[str, ...]:
        closure: set[str] = set()

        def visit(current: str) -> None:
            for child_id in view.children.get(current, ()):
                closure.add(child_id)
                visit(child_id)

        visit(delta_id)
        active_sequence: dict[str, int] = {}
        for event in view.events:
            if event.delta_id not in closure:
                continue
            if event.application_event == APPLY_EVENT:
                active_sequence[event.delta_id] = event.state_sequence
            else:
                active_sequence.pop(event.delta_id, None)
        return tuple(
            sorted(
                active_sequence,
                key=lambda member: (-active_sequence[member], member),
            )
        )

    def _reversal_plan(
        self, view: _LedgerView, delta: ParameterDelta
    ) -> tuple[_ReversalStep, ...]:
        if self._store.application_state(delta.delta_id).state != "applied":
            _reject("delta_not_applied")
        scope_key = _delta_scope_key(delta)
        plan_ids = (*self._applied_descendants(view, delta.delta_id), delta.delta_id)
        _root, current = self._fold(view, scope_key, byte_prove=True)
        assert current is not None
        steps: list[_ReversalStep] = []
        for delta_id in plan_ids:
            member = view.deltas.get(delta_id)
            if member is None:
                _reject("delta_unknown")
            if _delta_scope_key(member) != scope_key:
                _reject("reversal_scope_divergent")
            recomputed, inverse, tensor = self._prove_reverse(member, current)
            steps.append(
                _ReversalStep(
                    delta=member,
                    application_ordinal=(
                        self._store.application_state(delta_id).last_ordinal + 1
                    ),
                    base_payload_root=payload_root(current),
                    result_payload_root=payload_root(recomputed),
                    proof=ApplicationPayloadProof(
                        current, recomputed, tensor, inverse
                    ),
                )
            )
            current = recomputed
        return tuple(steps)

    def reverse(self, delta_raw: bytes) -> ApplyReceipt:
        """Byte-proof rollback of one delta with no applied children."""

        delta = self._authenticate(delta_raw)
        view = self._snapshot()
        blocking = self._applied_descendants(view, delta.delta_id)
        if blocking:
            _reject("reversal_order_violation", blocking=blocking)
        (step,) = self._reversal_plan(view, delta)
        return self._journal_and_commit(
            delta=step.delta,
            application_event=REVERSE_EVENT,
            application_ordinal=step.application_ordinal,
            state_sequence=view.next_sequence,
            base_payload_root=step.base_payload_root,
            result_payload_root=step.result_payload_root,
            proof=step.proof,
        )

    def cascade_reverse(self, delta_raw: bytes) -> tuple[ApplyReceipt, ...]:
        """Deterministic all-or-nothing reversal of a delta and its closure.

        The full ordered plan (children before parents, siblings in
        delta-id order) is computed and every byte proof validated before
        any event is appended; the events are then appended in plan order,
        each journal-guarded.
        """

        delta = self._authenticate(delta_raw)
        view = self._snapshot()
        steps = self._reversal_plan(view, delta)
        return self._commit_reversal_batch(steps, first_sequence=view.next_sequence)

    def recover(self) -> tuple[RecoveryOutcome, ...]:
        """Resolve every unresolved journaled intent: complete or abandon.

        Completion re-proves the intent from scratch and appends the event
        under the intent's deterministic operation identity (exactly-once
        through the operation ledger); any failure appends a typed
        ``apply_abandoned`` record instead.  State is consistent either
        way: no path re-applies or half-applies.
        """

        view = self._snapshot()
        committed = view.committed_application_ids()
        outcomes: list[RecoveryOutcome] = []
        for intent in view.intents:
            if intent.intent_event_id in view.abandoned_intent_ids:
                continue
            if intent.application_id in committed:
                continue
            try:
                outcome = self._complete_intent(intent)
            except ApplyRejection as error:
                self._append_abandoned(intent, error.code)
                outcome = RecoveryOutcome(
                    intent_event_id=intent.intent_event_id,
                    delta_id=intent.delta_id,
                    application_event=intent.application_event,
                    application_ordinal=intent.application_ordinal,
                    disposition="abandoned",
                    code=APPLY_ABANDONED_CODE,
                    cause=error.code,
                )
            outcomes.append(outcome)
        return tuple(outcomes)

    def _complete_intent(self, intent: ApplyIntent) -> RecoveryOutcome:
        view = self._snapshot()
        delta = view.deltas.get(intent.delta_id)
        if delta is None:
            _reject("delta_unknown")
        if _delta_scope_key(delta) != intent.scope_key:
            _reject("apply_intent_invalid")
        state = self._store.application_state(delta.delta_id)
        if state.last_ordinal + 1 != intent.application_ordinal:
            _reject("apply_intent_stale")
        if view.next_sequence != intent.state_sequence:
            _reject("apply_intent_stale")
        chain_root, current = self._fold(
            view, intent.scope_key, byte_prove=True
        )
        assert current is not None
        if chain_root != intent.base_payload_root:
            _reject("base_root_divergent")
        if intent.application_event == APPLY_EVENT:
            if state.state == "applied":
                _reject("delta_already_applied")
            post, inverse, tensor = self._prove_apply(delta, current)
            result_root = payload_root(post)
            proof = ApplicationPayloadProof(current, post, tensor, inverse)
        else:
            if state.state != "applied":
                _reject("delta_not_applied")
            recomputed, inverse, tensor = self._prove_reverse(delta, current)
            result_root = payload_root(recomputed)
            proof = ApplicationPayloadProof(current, recomputed, tensor, inverse)
        if result_root != intent.result_payload_root:
            _reject("apply_intent_invalid")
        document = _application_document(
            delta_id=intent.delta_id,
            application_event=intent.application_event,
            application_ordinal=intent.application_ordinal,
            state_sequence=intent.state_sequence,
            scope_key=intent.scope_key,
            base_payload_root=intent.base_payload_root,
            result_payload_root=intent.result_payload_root,
            tensor_payload_root=intent.tensor_payload_root,
            inverse_payload_root=intent.inverse_payload_root,
        )
        raw = canonicalize(dict(document))
        if plasticity_record_identity("delta_application", raw) != (
            intent.application_id
        ):
            _reject("apply_intent_invalid")
        admission = (
            self._admit(delta, proof)
            if intent.application_event == APPLY_EVENT
            else None
        )
        self._append_event(document, proof, admission)
        return RecoveryOutcome(
            intent_event_id=intent.intent_event_id,
            delta_id=intent.delta_id,
            application_event=intent.application_event,
            application_ordinal=intent.application_ordinal,
            disposition="completed",
            code="completed",
            cause="",
        )

    def current_parameter_root(
        self, scope_kind: str, *, project_id: str | None = None
    ) -> str:
        """The current parameter root of one scope, byte-proved by folding.

        Every apply/reverse event is recomputed through the kernel from
        the scope base payload in global sequence order, over records whose
        byte identity ``replay_verify`` has already re-proven.
        """

        scope_key = canonical_scope_key(scope_kind, project_id)
        view = self._snapshot()
        root, _bytes = self._fold(view, scope_key, byte_prove=True)
        return root

    def pending_intents(self) -> tuple[ApplyIntent, ...]:
        """Unresolved journaled intents, in deterministic sequence order."""

        view = self._snapshot()
        committed = view.committed_application_ids()
        return tuple(
            intent
            for intent in view.intents
            if intent.intent_event_id not in view.abandoned_intent_ids
            and intent.application_id not in committed
        )

    def application_events(
        self, scope_kind: str, *, project_id: str | None = None
    ) -> tuple[ApplicationEvent, ...]:
        """Committed application events for one scope in sequence order."""

        view = self._snapshot()
        scope_key = canonical_scope_key(scope_kind, project_id)
        return tuple(
            event for event in view.events if event.scope_key == scope_key
        )


__all__ = [
    "ABANDONED_SCHEMA_VERSION",
    "APPLICATION_SCHEMA_VERSION",
    "APPLY_ABANDONED_CODE",
    "ApplicationEvent",
    "ApplyCoordinator",
    "ApplyIntent",
    "ApplyReceipt",
    "canonical_scope_key",
    "ApplyRejection",
    "DIVERGENCE_CONTEXT_BYTES",
    "INTENT_SCHEMA_VERSION",
    "PAYLOAD_DOMAIN",
    "RecoveryOutcome",
    "abandon_operation_id",
    "delta_record_operation_id",
    "event_operation_id",
    "first_payload_divergence",
    "intent_operation_id",
    "payload_root",
]
