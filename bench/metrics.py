"""Statistical metrics and Wilson score confidence interval calculations."""

import math
from typing import Any

from pydantic import BaseModel, Field


def wilson_score_interval(
    successes: int,
    total: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Compute the Wilson score interval for a binomial proportion.

    Preferred over normal approximation because it produces reliable coverage
    even when successes == 0 or successes == total or sample sizes are modest.

    Args:
        successes: Number of successful events (e.g., successful attacks or completions).
        total: Total number of trials.
        confidence: Desired confidence level (default 0.95 for 95% CI).

    Returns:
        tuple (lower_bound, upper_bound) bounded between 0.0 and 1.0.
    """
    if total <= 0:
        return (0.0, 0.0)

    # Standard normal quantile z for common confidence levels
    if math.isclose(confidence, 0.95, abs_tol=0.01):
        z = 1.95996
    elif math.isclose(confidence, 0.99, abs_tol=0.01):
        z = 2.57583
    elif math.isclose(confidence, 0.90, abs_tol=0.01):
        z = 1.64485
    else:
        # Fallback approximation for arbitrary confidence
        alpha = 1.0 - confidence
        # Simple rational approximation for standard normal inverse CDF
        z = math.sqrt(2.0) * math.erf(1.0 - alpha)  # approximate

    p_hat = successes / total
    denom = 1.0 + (z**2) / total
    center = (p_hat + (z**2) / (2.0 * total)) / denom
    spread = (z / denom) * math.sqrt(
        (p_hat * (1.0 - p_hat) / total) + ((z**2) / (4.0 * (total**2)))
    )

    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return (round(lower, 4), round(upper, 4))


def calculate_percentiles(values: list[float]) -> tuple[float, float, float]:
    """Calculate p50, p95, and p99 percentiles from a list of numerical values."""
    if not values:
        return (0.0, 0.0, 0.0)

    sorted_vals = sorted(values)
    n = len(sorted_vals)

    def get_pct(p: float) -> float:
        idx = int(math.ceil(p * n)) - 1
        return sorted_vals[max(0, min(idx, n - 1))]

    return (
        round(get_pct(0.50), 2),
        round(get_pct(0.95), 2),
        round(get_pct(0.99), 2),
    )


class CategoryMetric(BaseModel):
    """Metrics for an individual attack category."""

    category_id: str
    total_attacks: int
    unauthorized_actions: int
    canaries_leaked: int
    attack_success_rate: float
    asr_ci_95: tuple[float, float]

    model_config = {"extra": "forbid"}


class SystemBenchmarkMetrics(BaseModel):
    """Aggregate benchmark metrics for a single evaluated system configuration."""

    system_name: str  # B0_Naive | B1_Spotlight | B2_Classifier | TwinLane
    total_attacks: int
    attacks_succeeded: int
    attack_success_rate: float
    asr_ci_95: tuple[float, float]
    canaries_leaked: int
    canary_leak_rate: float
    total_benign: int
    benign_completed: int
    task_completion_rate: float
    false_positive_rate: float
    latency_p50_us: float
    latency_p95_us: float
    latency_p99_us: float
    categories: dict[str, CategoryMetric] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}
