"""Pure, fixture-only market adapters with ten explicit interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import ClassVar

from .canonical import canonicalize, sha256_hex
from .evidence_contracts import FrozenObject, FrozenValue, _freeze
from .market_contracts import (
    CAPABILITY_KEYS,
    PAYLOAD_SCHEMA_ID,
    AdapterDescriptor,
    AdapterIdentity,
    MarketContract,
)


INTERFACE_NAMES = CAPABILITY_KEYS


class MarketAdapterRejection(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _thaw(value: FrozenValue) -> object:
    if isinstance(value, FrozenObject):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class AdapterResult:
    interface: str
    state: str
    value: FrozenValue
    reason: str | None
    content_sha256: str

    @classmethod
    def supported(cls, interface: str, value: object) -> "AdapterResult":
        frozen = _freeze(value)
        body = {"interface": interface, "state": "supported", "value": value}
        return cls(interface, "supported", frozen, None, sha256_hex(canonicalize(body)))

    @classmethod
    def unsupported(cls, interface: str, reason: str) -> "AdapterResult":
        body = {"interface": interface, "reason": reason, "state": "unsupported"}
        return cls(interface, "unsupported", None, reason, sha256_hex(canonicalize(body)))

    def as_value(self) -> dict[str, object]:
        return {
            "content_sha256": self.content_sha256,
            "interface": self.interface,
            "reason": self.reason,
            "state": self.state,
            "value": _thaw(self.value),
        }


class MarketAdapter(ABC):
    """Static interface; dynamic capability lookup is intentionally absent."""

    @property
    @abstractmethod
    def identity(self) -> AdapterIdentity: ...

    @property
    @abstractmethod
    def descriptor(self) -> AdapterDescriptor: ...

    @abstractmethod
    def discovery(self, contract: MarketContract) -> AdapterResult: ...

    @abstractmethod
    def normalization(self, contract: MarketContract) -> AdapterResult: ...

    @abstractmethod
    def calendar_session(self, contract: MarketContract) -> AdapterResult: ...

    @abstractmethod
    def lifecycle(self, contract: MarketContract) -> AdapterResult: ...

    @abstractmethod
    def correction(self, contract: MarketContract) -> AdapterResult: ...

    @abstractmethod
    def cost(self, contract: MarketContract) -> AdapterResult: ...

    @abstractmethod
    def fill(self, contract: MarketContract) -> AdapterResult: ...

    @abstractmethod
    def failure(self, contract: MarketContract) -> AdapterResult: ...

    @abstractmethod
    def settlement(self, contract: MarketContract) -> AdapterResult: ...

    @abstractmethod
    def capability(self, contract: MarketContract) -> AdapterResult: ...


@dataclass(frozen=True, slots=True)
class ListedCashEquityAdapter(MarketAdapter):
    descriptor: AdapterDescriptor

    @property
    def identity(self) -> AdapterIdentity:
        return self.descriptor.identity

    def _payload(self, contract: MarketContract) -> Mapping[str, FrozenValue]:
        if not isinstance(contract, MarketContract):
            raise MarketAdapterRejection("validated_market_contract_required")
        if contract.value["family"] != self.identity.family:
            raise MarketAdapterRejection("adapter_family_mismatch")
        if contract.value["payload_schema_id"] != PAYLOAD_SCHEMA_ID:
            raise MarketAdapterRejection("adapter_payload_schema_mismatch")
        payload = contract.value["payload"]
        if not isinstance(payload, FrozenObject):
            raise MarketAdapterRejection("adapter_payload_invalid")
        return payload

    def discovery(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.supported(
            "discovery", {"stable_identity_id": contract.value["stable_identity_id"]}
        )

    def normalization(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.supported(
            "normalization",
            {
                "envelope_sha256": contract.canonical_sha256,
                "payload_sha256": contract.payload_sha256,
            },
        )

    def calendar_session(self, contract: MarketContract) -> AdapterResult:
        payload = self._payload(contract)
        return AdapterResult.supported("calendar_session", _thaw(payload["session"]))

    def lifecycle(self, contract: MarketContract) -> AdapterResult:
        payload = self._payload(contract)
        session = payload["session"]
        assert isinstance(session, FrozenObject)
        return AdapterResult.supported(
            "lifecycle", {"state": "quotable" if session["state"] == "regular" else "closed"}
        )

    def correction(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.supported("correction", {"correction_of": None})

    def cost(self, contract: MarketContract) -> AdapterResult:
        payload = self._payload(contract)
        spread = Decimal(str(payload["ask"])) - Decimal(str(payload["bid"]))
        return AdapterResult.supported(
            "cost", {"currency": payload["currency"], "spread": format(spread, "f")}
        )

    def fill(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.unsupported("fill", "advisory-only")

    def failure(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.supported("failure", {"state": "none"})

    def settlement(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.unsupported("settlement", "advisory-only")

    def capability(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.supported(
            "capability",
            {
                name: {
                    "reason": disposition.reason,
                    "state": disposition.state,
                }
                for name, disposition in self.descriptor.capabilities.items()
            },
        )


@dataclass(frozen=True, slots=True)
class _StructuredFamilyAdapter(MarketAdapter):
    """Shared pure interface plumbing without sharing family lifecycle semantics."""

    descriptor: AdapterDescriptor
    FAMILY: ClassVar[str]
    PAYLOAD_SCHEMA: ClassVar[str]

    @property
    def identity(self) -> AdapterIdentity:
        return self.descriptor.identity

    def _payload(self, contract: MarketContract) -> FrozenObject:
        if not isinstance(contract, MarketContract):
            raise MarketAdapterRejection("validated_market_contract_required")
        if self.identity.family != self.FAMILY or contract.value["family"] != self.FAMILY:
            raise MarketAdapterRejection("adapter_family_mismatch")
        if contract.value["payload_schema_id"] != self.PAYLOAD_SCHEMA:
            raise MarketAdapterRejection("adapter_payload_schema_mismatch")
        payload = contract.value["payload"]
        if not isinstance(payload, FrozenObject):
            raise MarketAdapterRejection("adapter_payload_invalid")
        return payload

    def discovery(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.supported("discovery", {"stable_identity_id": contract.value["stable_identity_id"]})

    def normalization(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.supported("normalization", {"envelope_sha256": contract.canonical_sha256, "payload_sha256": contract.payload_sha256})

    def calendar_session(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.unsupported("calendar_session", "family-clock-owned")

    def lifecycle(self, contract: MarketContract) -> AdapterResult:
        payload = self._payload(contract)
        return AdapterResult.supported("lifecycle", {"family": self.FAMILY, "state": payload["lifecycle_state"]})

    def correction(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.supported("correction", {"evidence_required": True})

    def cost(self, contract: MarketContract) -> AdapterResult:
        payload = self._payload(contract)
        return AdapterResult.supported("cost", {"fee_basis_id": payload["fee_basis_id"] if "fee_basis_id" in payload else payload.get("payout_basis_id")})

    def fill(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.unsupported("fill", "advisory-only")

    def failure(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.supported("failure", {"state": "none"})

    def settlement(self, contract: MarketContract) -> AdapterResult:
        payload = self._payload(contract)
        basis = (
            payload["settlement_basis_id"]
            if "settlement_basis_id" in payload
            else payload["final_settlement_basis_id"]
        )
        return AdapterResult.supported("settlement", {"settlement_basis_id": basis})

    def capability(self, contract: MarketContract) -> AdapterResult:
        self._payload(contract)
        return AdapterResult.supported("capability", {name: disposition.state for name, disposition in self.descriptor.capabilities.items()})


class ListedOptionAdapter(_StructuredFamilyAdapter):
    FAMILY = "listed_option"
    PAYLOAD_SCHEMA = "https://schemas.skeleton.local/v1/market-listed-option-payload.schema.json"


class FutureAdapter(_StructuredFamilyAdapter):
    FAMILY = "future"
    PAYLOAD_SCHEMA = "https://schemas.skeleton.local/v1/market-future-payload.schema.json"


class ContingentContractAdapter(_StructuredFamilyAdapter):
    FAMILY = "contingent_contract"
    PAYLOAD_SCHEMA = "https://schemas.skeleton.local/v1/market-contingent-payload.schema.json"


class SportsEventContractAdapter(_StructuredFamilyAdapter):
    FAMILY = "sports_event_contract"
    PAYLOAD_SCHEMA = "https://schemas.skeleton.local/v1/market-sports-event-payload.schema.json"


@dataclass(frozen=True, slots=True, init=False)
class MarketAdapterRegistry:
    identities: tuple[str, ...]
    _adapters: Mapping[str, MarketAdapter]

    def __init__(self, adapters: Sequence[MarketAdapter]) -> None:
        if not adapters:
            raise MarketAdapterRejection("adapter_registry_empty")
        values: dict[str, MarketAdapter] = {}
        for adapter in adapters:
            if not isinstance(adapter, MarketAdapter):
                raise MarketAdapterRejection("market_adapter_required")
            identity = adapter.identity.canonical_id
            if identity in values:
                raise MarketAdapterRejection("duplicate_adapter_identity")
            values[identity] = adapter
        ordered = dict(sorted(values.items(), key=lambda item: item[0]))
        object.__setattr__(self, "identities", tuple(ordered))
        object.__setattr__(self, "_adapters", MappingProxyType(ordered))

    def trace(self, identity: str, contract: MarketContract) -> tuple[AdapterResult, ...]:
        try:
            adapter = self._adapters[identity]
        except KeyError as error:
            raise MarketAdapterRejection("adapter_identity_unknown") from error
        if not isinstance(contract, MarketContract):
            raise MarketAdapterRejection("validated_market_contract_required")
        if contract.value["family"] != adapter.identity.family:
            raise MarketAdapterRejection("adapter_family_mismatch")
        results = (
            adapter.discovery(contract),
            adapter.normalization(contract),
            adapter.calendar_session(contract),
            adapter.lifecycle(contract),
            adapter.correction(contract),
            adapter.cost(contract),
            adapter.fill(contract),
            adapter.failure(contract),
            adapter.settlement(contract),
            adapter.capability(contract),
        )
        if tuple(result.interface for result in results) != INTERFACE_NAMES:
            raise MarketAdapterRejection("adapter_interface_inventory")
        for result in results:
            declared = adapter.descriptor.capabilities[result.interface]
            if declared.state != result.state:
                raise MarketAdapterRejection("adapter_capability_disposition_mismatch")
            if result.state == "unsupported" and declared.reason != result.reason:
                raise MarketAdapterRejection("adapter_capability_disposition_mismatch")
        return results
