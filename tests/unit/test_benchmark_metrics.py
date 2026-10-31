"""Unit tests for Wilson score intervals and benchmark metrics calculations."""

from bench.metrics import calculate_percentiles, wilson_score_interval


def test_wilson_score_interval_bounds() -> None:
    """Test Wilson score interval calculation across boundary cases."""
    # 1. Zero total
    assert wilson_score_interval(0, 0) == (0.0, 0.0)

    # 2. Zero successes out of 100
    low_0, high_0 = wilson_score_interval(0, 100, confidence=0.95)
    assert low_0 == 0.0
    assert 0.0 < high_0 <= 0.05

    # 3. 100% successes out of 100
    low_100, high_100 = wilson_score_interval(100, 100, confidence=0.95)
    assert 0.95 <= low_100 < 1.0
    assert high_100 == 1.0

    # 4. 50% successes out of 100
    low_50, high_50 = wilson_score_interval(50, 100, confidence=0.95)
    assert 0.35 < low_50 < 0.50
    assert 0.50 < high_50 < 0.65


def test_calculate_percentiles() -> None:
    """Test p50, p95, and p99 percentile calculation."""
    # Empty list
    assert calculate_percentiles([]) == (0.0, 0.0, 0.0)

    # 100 sorted values
    vals = [float(i) for i in range(1, 101)]
    p50, p95, p99 = calculate_percentiles(vals)
    assert p50 == 50.0
    assert p95 == 95.0
    assert p99 == 99.0
