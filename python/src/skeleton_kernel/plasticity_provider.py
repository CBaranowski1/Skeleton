"""Authenticated provider boundary for Phase 13 adapter training and loading."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol, runtime_checkable

from .canonical import canonicalize, parse_raw_json
from .plasticity_kernel import tensor_payload_root
from .plasticity_store import (
    PlasticityAuthorityRejection,
    ProviderLifecycleAppend,
    plasticity_record_identity,
    verify_owner_capability,
)


_TRAINING_DOMAIN = b"SKELETON_PHASE13_PROVIDER_TRAINING_RECEIPT_V1"
_VERIFICATION_DOMAIN = b"SKELETON_PHASE13_PROVIDER_LOAD_VERIFICATION_V1"
_SNAPSHOT_DOMAIN = b"SKELETON_PHASE13_PROVIDER_SNAPSHOT_V1"
_ACTIVATION_TOKEN = object()


class PlasticityProviderRejection(ValueError):
    """Closed provider-boundary failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: str) -> None:
    raise PlasticityProviderRejection(code)


def _framed(domain: bytes, raw: bytes) -> str:
    return sha256(
        len(domain).to_bytes(8, "big")
        + domain
        + len(raw).to_bytes(8, "big")
        + raw
    ).hexdigest()


def adapter_root(adapter_bytes: bytes) -> str:
    if not isinstance(adapter_bytes, bytes) or not adapter_bytes:
        _reject("provider_adapter_bytes_invalid")
    # Adapter payloads are the same canonical tensor bytes authenticated by
    # ``parameter_deltas.tensor_payload_root``.  One byte string must have one
    # identity at both the provider and application boundaries.
    return tensor_payload_root(adapter_bytes)


def snapshot_identity(state_bytes: bytes) -> str:
    if not isinstance(state_bytes, bytes) or not state_bytes:
        _reject("provider_snapshot_bytes_invalid")
    return _framed(_SNAPSHOT_DOMAIN, state_bytes)


@dataclass(frozen=True, slots=True)
class ProviderSnapshot:
    snapshot_id: str
    state_bytes: bytes

    def authenticate(self) -> "ProviderSnapshot":
        if self.snapshot_id != snapshot_identity(self.state_bytes):
            _reject("provider_snapshot_identity_mismatch")
        return self


@dataclass(frozen=True, slots=True)
class ProviderTrainingResult:
    adapter_bytes: bytes
    loss_before: int
    loss_after: int


@dataclass(frozen=True, slots=True)
class TrainingReceipt:
    receipt_id: str
    base_snapshot_id: str
    batch_root: str
    adapter_root: str
    loss_before: int
    loss_after: int
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class LoadVerification:
    verification_id: str
    base_snapshot_id: str
    adapter_root: str
    staged_handle: str
    canonical_bytes: bytes


class ProviderActivationEvidence:
    """Opaque live-provider proof emitted only after verified activation."""

    __slots__ = (
        "_adapter_root",
        "_authorization_sha256",
        "_base_snapshot_id",
        "_loaded_snapshot_id",
        "_operation_id",
        "_lifecycle_receipt_ids",
        "_provider",
        "_verification_id",
    )

    def __init__(
        self,
        *,
        base_snapshot_id: str,
        loaded_snapshot_id: str,
        adapter_digest: str,
        verification_id: str,
        operation_id: str,
        authorization_sha256: str,
        lifecycle_receipt_ids: tuple[str, str, str],
        provider: PlasticityProvider,
        token: object,
    ) -> None:
        if token is not _ACTIVATION_TOKEN:
            raise TypeError("provider activation evidence requires a verified load")
        self._base_snapshot_id = base_snapshot_id
        self._loaded_snapshot_id = loaded_snapshot_id
        self._adapter_root = adapter_digest
        self._verification_id = verification_id
        self._operation_id = operation_id
        self._authorization_sha256 = authorization_sha256
        self._lifecycle_receipt_ids = lifecycle_receipt_ids
        self._provider = provider

    @property
    def base_snapshot_id(self) -> str:
        return self._base_snapshot_id

    @property
    def loaded_snapshot_id(self) -> str:
        return self._loaded_snapshot_id

    @property
    def adapter_root(self) -> str:
        return self._adapter_root

    @property
    def verification_id(self) -> str:
        return self._verification_id

    @property
    def operation_id(self) -> str:
        return self._operation_id

    @property
    def authorization_sha256(self) -> str:
        return self._authorization_sha256

    @property
    def lifecycle_receipt_ids(self) -> tuple[str, str, str]:
        return self._lifecycle_receipt_ids

    def _authorizes_live_activation(
        self, *, base_snapshot_id: str, adapter_digest: str
    ) -> bool:
        try:
            live = self._provider.current_snapshot().authenticate()
        except Exception:
            return False
        return (
            self._base_snapshot_id == base_snapshot_id
            and self._adapter_root == adapter_digest
            and live.snapshot_id == self._loaded_snapshot_id
        )


@runtime_checkable
class PlasticityProvider(Protocol):
    """Narrow authority-free provider lifecycle required by Phase 13."""

    def current_snapshot(self) -> ProviderSnapshot: ...

    def training_step(
        self, base_snapshot_id: str, batch_bytes: bytes
    ) -> ProviderTrainingResult: ...

    def stage_adapter(self, adapter_bytes: bytes) -> str: ...

    def staged_adapter_bytes(self, staged_handle: str) -> bytes: ...

    def verify_staged(
        self, staged_handle: str, base_snapshot_id: str, adapter_digest: str
    ) -> bool: ...

    def activate(
        self, staged_handle: str, verification_id: str
    ) -> ProviderSnapshot: ...

    def unload(self, loaded_snapshot_id: str) -> ProviderSnapshot: ...


class ProviderCoordinator:
    """Authenticate training, verify-before-load, and byte-exact restore."""

    __slots__ = (
        "_activation_evidence",
        "_base",
        "_consumed_authorizations",
        "_loaded",
        "_lifecycle_store",
        "_provider",
        "_recorded_at",
        "_writer_id",
        "_fence_id",
        "_generation",
    )

    def __init__(
        self,
        provider: PlasticityProvider,
        *,
        lifecycle_store: object,
        writer_id: str,
        fence_id: str,
        generation: int,
        recorded_at: str,
    ) -> None:
        if not isinstance(provider, PlasticityProvider):
            _reject("provider_protocol_invalid")
        self._provider = provider
        append_lifecycle = getattr(lifecycle_store, "_append_provider_lifecycle", None)
        if not callable(append_lifecycle):
            _reject("provider_lifecycle_store_required")
        self._lifecycle_store = lifecycle_store
        self._writer_id = writer_id
        self._fence_id = fence_id
        self._generation = generation
        self._recorded_at = recorded_at
        self._base = provider.current_snapshot().authenticate()
        self._loaded: ProviderSnapshot | None = None
        self._activation_evidence: ProviderActivationEvidence | None = None
        self._consumed_authorizations: set[str] = set()

    def _persist_lifecycle(
        self,
        *,
        lifecycle_event: str,
        operation_id: str,
        base_snapshot_id: str,
        observed_snapshot_id: str,
        adapter_digest: str,
        evidence_root: str,
        authorization,
    ) -> str:
        value = {
            "schema_version": "skeleton.provider-lifecycle-receipt.v1",
            "record_type": "provider_lifecycle_receipt",
            "lifecycle_event": lifecycle_event,
            "operation_id": operation_id,
            "base_snapshot_id": base_snapshot_id,
            "observed_snapshot_id": observed_snapshot_id,
            "adapter_root": adapter_digest,
            "evidence_root": evidence_root,
            "authorization_sha256": authorization.capability_sha256,
            "owner_capability": parse_raw_json(authorization.canonical_bytes),
            "fence_id": self._fence_id,
            "generation": self._generation,
            "attempt_ordinal": authorization.attempt_ordinal,
        }
        raw = canonicalize(value)
        receipt_id = plasticity_record_identity("provider_lifecycle", raw)
        item = ProviderLifecycleAppend(
            receipt_id,
            lifecycle_event,
            operation_id,
            base_snapshot_id,
            observed_snapshot_id,
            adapter_digest,
            evidence_root,
            authorization.capability_sha256,
            self._fence_id,
            self._generation,
            authorization.attempt_ordinal,
            self._recorded_at,
            raw,
        )
        self._lifecycle_store._append_provider_lifecycle(
            item,
            authorization=authorization,
            writer_id=self._writer_id,
            operation_id=sha256(
                f"{operation_id}:{lifecycle_event}".encode("ascii")
            ).hexdigest(),
        )
        return receipt_id

    @property
    def active_snapshot_id(self) -> str:
        return self._provider.current_snapshot().authenticate().snapshot_id

    def _authorize(
        self,
        raw: bytes,
        *,
        operation: str,
        operation_id: str,
        provider_snapshot_id: str,
        subject_root: str,
        attempt_ordinal: int,
    ):
        try:
            authorization = verify_owner_capability(
                raw,
                operation=operation,
                operation_id=operation_id,
                provider_snapshot_id=provider_snapshot_id,
                subject_root=subject_root,
                attempt_ordinal=attempt_ordinal,
            )
        except PlasticityAuthorityRejection as error:
            raise PlasticityProviderRejection(error.code) from error
        if authorization.capability_sha256 in self._consumed_authorizations:
            _reject("provider_authority_replayed")
        self._consumed_authorizations.add(authorization.capability_sha256)
        return authorization

    def training_step(
        self,
        batch_bytes: bytes,
        *,
        operation_id: str,
        attempt_ordinal: int,
        owner_capability: bytes,
    ) -> TrainingReceipt:
        if not isinstance(batch_bytes, bytes) or not batch_bytes:
            _reject("provider_training_batch_invalid")
        current = self._provider.current_snapshot().authenticate()
        if current.snapshot_id != self._base.snapshot_id or self._loaded is not None:
            _reject("provider_training_base_snapshot_mismatch")
        batch_root = sha256(batch_bytes).hexdigest()
        authorization = self._authorize(
            owner_capability,
            operation="training",
            operation_id=operation_id,
            provider_snapshot_id=current.snapshot_id,
            subject_root=batch_root,
            attempt_ordinal=attempt_ordinal,
        )
        result = self._provider.training_step(current.snapshot_id, batch_bytes)
        if not isinstance(result, ProviderTrainingResult):
            _reject("provider_training_result_invalid")
        if (
            type(result.loss_before) is not int
            or type(result.loss_after) is not int
            or result.loss_before < 0
            or result.loss_after < 0
        ):
            _reject("provider_training_metrics_invalid")
        value = {
            "schema_version": "skeleton.provider-training-receipt.v1",
            "record_type": "provider_training_receipt",
            "operation_id": authorization.operation_id,
            "attempt_ordinal": authorization.attempt_ordinal,
            "authorization_sha256": authorization.capability_sha256,
            "base_snapshot_id": current.snapshot_id,
            "batch_root": batch_root,
            "adapter_root": adapter_root(result.adapter_bytes),
            "loss_before": result.loss_before,
            "loss_after": result.loss_after,
        }
        raw = canonicalize(value)
        self._persist_lifecycle(
            lifecycle_event="training",
            operation_id=authorization.operation_id,
            base_snapshot_id=current.snapshot_id,
            observed_snapshot_id=current.snapshot_id,
            adapter_digest=str(value["adapter_root"]),
            evidence_root=batch_root,
            authorization=authorization,
        )
        return TrainingReceipt(
            _framed(_TRAINING_DOMAIN, raw),
            current.snapshot_id,
            str(value["batch_root"]),
            str(value["adapter_root"]),
            result.loss_before,
            result.loss_after,
            raw,
        )

    def load_adapter(
        self,
        adapter_bytes: bytes,
        *,
        expected_base_snapshot_id: str,
        operation_id: str,
        attempt_ordinal: int,
        owner_capability: bytes,
    ) -> tuple[ProviderSnapshot, LoadVerification]:
        if self._loaded is not None:
            _reject("provider_adapter_already_loaded")
        current = self._provider.current_snapshot().authenticate()
        if current.snapshot_id != expected_base_snapshot_id:
            _reject("provider_load_base_snapshot_mismatch")
        digest = adapter_root(adapter_bytes)
        authorization = self._authorize(
            owner_capability,
            operation="load",
            operation_id=operation_id,
            provider_snapshot_id=current.snapshot_id,
            subject_root=digest,
            attempt_ordinal=attempt_ordinal,
        )
        handle = self._provider.stage_adapter(adapter_bytes)
        if not isinstance(handle, str) or not handle:
            _reject("provider_stage_handle_invalid")
        if self._provider.staged_adapter_bytes(handle) != adapter_bytes:
            _reject("provider_staged_bytes_mismatch")
        stage_receipt_id = self._persist_lifecycle(
            lifecycle_event="stage",
            operation_id=authorization.operation_id,
            base_snapshot_id=current.snapshot_id,
            observed_snapshot_id=current.snapshot_id,
            adapter_digest=digest,
            evidence_root=sha256(handle.encode("utf-8")).hexdigest(),
            authorization=authorization,
        )
        if not self._provider.verify_staged(handle, current.snapshot_id, digest):
            _reject("provider_staged_verification_failed")
        value = {
            "schema_version": "skeleton.provider-load-verification.v1",
            "record_type": "provider_load_verification",
            "operation_id": authorization.operation_id,
            "attempt_ordinal": authorization.attempt_ordinal,
            "authorization_sha256": authorization.capability_sha256,
            "base_snapshot_id": current.snapshot_id,
            "adapter_root": digest,
            "staged_handle": handle,
        }
        raw = canonicalize(value)
        verification = LoadVerification(
            _framed(_VERIFICATION_DOMAIN, raw),
            current.snapshot_id,
            digest,
            handle,
            raw,
        )
        verification_receipt_id = self._persist_lifecycle(
            lifecycle_event="verification",
            operation_id=authorization.operation_id,
            base_snapshot_id=current.snapshot_id,
            observed_snapshot_id=current.snapshot_id,
            adapter_digest=digest,
            evidence_root=verification.verification_id,
            authorization=authorization,
        )
        try:
            loaded = self._provider.activate(handle, verification.verification_id)
            if not isinstance(loaded, ProviderSnapshot):
                _reject("provider_activation_result_invalid")
            loaded.authenticate()
            actual = self._provider.current_snapshot()
            if not isinstance(actual, ProviderSnapshot):
                _reject("provider_activation_result_invalid")
            actual.authenticate()
            if actual != loaded:
                _reject("provider_activation_snapshot_mismatch")
            if loaded.snapshot_id == current.snapshot_id:
                _reject("provider_activation_unchanged")
        except BaseException as error:
            self._restore_after_failed_activation(
                current,
                error,
                operation_id=authorization.operation_id,
                adapter_digest=digest,
                authorization=authorization,
            )
        self._loaded = loaded
        activation_receipt_id = self._persist_lifecycle(
            lifecycle_event="activation",
            operation_id=authorization.operation_id,
            base_snapshot_id=current.snapshot_id,
            observed_snapshot_id=loaded.snapshot_id,
            adapter_digest=digest,
            evidence_root=loaded.snapshot_id,
            authorization=authorization,
        )
        self._activation_evidence = ProviderActivationEvidence(
            base_snapshot_id=current.snapshot_id,
            loaded_snapshot_id=loaded.snapshot_id,
            adapter_digest=digest,
            verification_id=verification.verification_id,
            operation_id=authorization.operation_id,
            authorization_sha256=authorization.capability_sha256,
            lifecycle_receipt_ids=(
                stage_receipt_id,
                verification_receipt_id,
                activation_receipt_id,
            ),
            provider=self._provider,
            token=_ACTIVATION_TOKEN,
        )
        return loaded, verification

    def activation_evidence(
        self, *, expected_base_snapshot_id: str, adapter_digest: str
    ) -> ProviderActivationEvidence:
        evidence = self._activation_evidence
        if evidence is None or self._loaded is None:
            _reject("provider_verified_load_required")
        live = self._provider.current_snapshot().authenticate()
        if (
            live != self._loaded
            or evidence.loaded_snapshot_id != live.snapshot_id
            or evidence.base_snapshot_id != expected_base_snapshot_id
            or evidence.adapter_root != adapter_digest
        ):
            _reject("provider_live_snapshot_mismatch")
        return evidence

    def unload(
        self,
        *,
        operation_id: str,
        attempt_ordinal: int,
        owner_capability: bytes,
    ) -> ProviderSnapshot:
        if self._loaded is None:
            _reject("provider_adapter_not_loaded")
        current = self._provider.current_snapshot().authenticate()
        authorization = self._authorize(
            owner_capability,
            operation="unload",
            operation_id=operation_id,
            provider_snapshot_id=current.snapshot_id,
            subject_root=current.snapshot_id,
            attempt_ordinal=attempt_ordinal,
        )
        adapter_digest = self._activation_evidence.adapter_root if self._activation_evidence else (
            sha256(b"provider-adapter-unavailable").hexdigest()
        )
        self._persist_lifecycle(
            lifecycle_event="unload",
            operation_id=operation_id,
            base_snapshot_id=self._base.snapshot_id,
            observed_snapshot_id=current.snapshot_id,
            adapter_digest=adapter_digest,
            evidence_root=current.snapshot_id,
            authorization=authorization,
        )
        # The unload capability was verified and consumed by the durable
        # intent above; the external transition now runs under that receipt.
        restored = self._provider.unload(self._loaded.snapshot_id).authenticate()
        actual = self._provider.current_snapshot().authenticate()
        if restored != self._base or actual != self._base:
            _reject("provider_unload_restore_mismatch")
        self._persist_lifecycle(
            lifecycle_event="restoration",
            operation_id=operation_id,
            base_snapshot_id=self._base.snapshot_id,
            observed_snapshot_id=current.snapshot_id,
            adapter_digest=adapter_digest,
            evidence_root=restored.snapshot_id,
            authorization=authorization,
        )
        self._loaded = None
        self._activation_evidence = None
        return restored

    def _restore_after_failed_activation(
        self,
        expected: ProviderSnapshot,
        cause: BaseException,
        *,
        operation_id: str,
        adapter_digest: str,
        authorization,
    ) -> None:
        """Restore and durably close a failed activation before surfacing it."""

        try:
            actual = self._provider.current_snapshot()
            if not isinstance(actual, ProviderSnapshot):
                raise PlasticityProviderRejection("provider_activation_restore_failed")
            actual.authenticate()
            if actual != expected:
                restored = self._provider.unload(actual.snapshot_id)
                if not isinstance(restored, ProviderSnapshot):
                    raise PlasticityProviderRejection(
                        "provider_activation_restore_failed"
                    )
                restored.authenticate()
                observed = self._provider.current_snapshot().authenticate()
                if restored != expected or observed != expected:
                    raise PlasticityProviderRejection(
                        "provider_activation_restore_failed"
                    )
            self._persist_lifecycle(
                lifecycle_event="restoration",
                operation_id=operation_id,
                base_snapshot_id=expected.snapshot_id,
                observed_snapshot_id=expected.snapshot_id,
                adapter_digest=adapter_digest,
                evidence_root=expected.snapshot_id,
                authorization=authorization,
            )
        except BaseException as restore_error:
            if isinstance(restore_error, PlasticityProviderRejection) and (
                restore_error.code == "provider_activation_restore_failed"
            ):
                raise
            raise PlasticityProviderRejection(
                "provider_activation_restore_failed"
            ) from restore_error
        raise cause


__all__ = [
    "LoadVerification",
    "PlasticityProvider",
    "PlasticityProviderRejection",
    "ProviderActivationEvidence",
    "ProviderCoordinator",
    "ProviderSnapshot",
    "ProviderTrainingResult",
    "TrainingReceipt",
    "adapter_root",
    "snapshot_identity",
]
