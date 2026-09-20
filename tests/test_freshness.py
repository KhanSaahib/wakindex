"""Description: Regression tests for freshness across offsets, expiry, and clock changes."""

import pytest

from wakindex.graph import ContractError, Freshness


def test_expired_evidence_with_negative_offset_is_stale():
    fresh = Freshness("2026-09-20T13:00:00Z", "2026-09-20T14:00:00Z")
    assert fresh.as_of("2026-09-20T10:00:00-05:00").stale


def test_future_expiry_with_negative_offset_is_not_stale():
    fresh = Freshness("2026-09-20T09:00:00-05:00", "2026-09-20T10:00:00-05:00")
    assert not fresh.as_of("2026-09-20T14:30:00Z").stale


def test_expiry_equality_is_stale():
    fresh = Freshness("2026-09-20T13:00:00Z", "2026-09-20T14:00:00Z")
    assert fresh.as_of("2026-09-20T09:00:00-05:00").stale


def test_clock_regression_cannot_clear_staleness():
    fresh = Freshness("2026-09-20T13:00:00Z", "2026-09-20T14:00:00Z", stale=True)
    assert fresh.as_of("2026-09-20T13:30:00Z").stale


@pytest.mark.parametrize("timestamp", ["bad", "2026-09-20", "2026-09-20T14:00:00",
                                        "2026-09-20T14:00:00-00:00"])
def test_naive_or_invalid_timestamps_are_rejected(timestamp):
    with pytest.raises(ContractError, match="timestamp"):
        Freshness(timestamp, "2026-09-20T15:00:00Z")
    fresh = Freshness("2026-09-20T13:00:00Z", "2026-09-20T14:00:00Z")
    with pytest.raises(ContractError, match="timestamp"):
        fresh.as_of(timestamp)


def test_reversed_window_is_rejected():
    with pytest.raises(ContractError, match="valid_until"):
        Freshness("2026-09-20T10:00:00-05:00", "2026-09-20T14:00:00Z")


def test_serialized_stale_value_must_be_boolean():
    with pytest.raises(ContractError, match="stale"):
        Freshness.from_dict({"collected_at": "2026-09-20T13:00:00Z",
                             "valid_until": "2026-09-20T14:00:00Z", "stale": "false"})
