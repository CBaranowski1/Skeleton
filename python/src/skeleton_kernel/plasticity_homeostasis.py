"""Frozen deterministic homeostasis policy for Phase 13 admission."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


HOMEOSTASIS_PROFILE_ID = "skeleton.plasticity-homeostasis-profile.v1"
HOMEOSTASIS_CAPS = MappingProxyType(
    {
        "application_frequency": 1000,
        "delta_count": 100,
        "delta_magnitude": 1000,
        "drift": 1000,
        "kl_divergence": 1000,
        "rank": 64,
        "regression_loss": 1000,
        "storage_bytes": 1_000_000,
        "training_compute": 1000,
    }
)
HOMEOSTASIS_ADMISSION_BUDGETS = tuple(sorted(HOMEOSTASIS_CAPS))


class HomeostasisRejection(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class HomeostasisDecision:
    cap_amount: int
    amount_before: int
    attempted_amount: int
    committed_amount: int
    amount_after: int
    utilization_permille: int
    band: str
    action: str


def budget_cap(budget_kind: str) -> int:
    cap = HOMEOSTASIS_CAPS.get(budget_kind)
    if cap is None:
        raise HomeostasisRejection("homeostasis_budget_unknown")
    return cap


def derive_homeostasis_decision(
    *, budget_kind: str, amount_before: int, attempted_amount: int
) -> HomeostasisDecision:
    """Derive the only valid admission decision using exact integers."""

    if (
        type(amount_before) is not int
        or type(attempted_amount) is not int
        or amount_before < 0
        or attempted_amount < 0
    ):
        raise HomeostasisRejection("homeostasis_amount_invalid")
    cap = budget_cap(budget_kind)
    if amount_before > cap or attempted_amount > cap - amount_before:
        raise HomeostasisRejection("homeostasis_cap_exceeded")
    projected = amount_before + attempted_amount
    utilization = (projected * 1000) // cap if cap else 1000
    if utilization <= 500:
        band, action, committed = "nominal", "admit", attempted_amount
    elif utilization <= 750:
        band, action, committed = "elevated", "admit", attempted_amount
    elif utilization <= 900:
        band, action, committed = "high", "clamp_magnitude", attempted_amount
    elif utilization < 1000:
        band, action, committed = "high", "defer_admission", 0
    else:
        # Reaching the hard ceiling records no new allocation; an exact-cap
        # request is fail-closed just like cap+1.
        raise HomeostasisRejection("homeostasis_cap_exceeded")
    return HomeostasisDecision(
        cap_amount=cap,
        amount_before=amount_before,
        attempted_amount=attempted_amount,
        committed_amount=committed,
        amount_after=amount_before + committed,
        utilization_permille=utilization,
        band=band,
        action=action,
    )


__all__ = [
    "HOMEOSTASIS_ADMISSION_BUDGETS",
    "HOMEOSTASIS_CAPS",
    "HOMEOSTASIS_PROFILE_ID",
    "HomeostasisDecision",
    "HomeostasisRejection",
    "budget_cap",
    "derive_homeostasis_decision",
]
