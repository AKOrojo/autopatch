import pytest
from datetime import datetime, timezone
from src.api.services.dashboard_service import compute_date_range


def test_compute_date_range_7d():
    end = datetime(2026, 4, 9, tzinfo=timezone.utc)
    start, end_dt = compute_date_range("7d", end_override=end)
    assert (end_dt - start).days == 7


def test_compute_date_range_30d():
    end = datetime(2026, 4, 9, tzinfo=timezone.utc)
    start, end_dt = compute_date_range("30d", end_override=end)
    assert (end_dt - start).days == 30


def test_compute_date_range_custom():
    start, end_dt = compute_date_range(None, start_str="2026-03-01T00:00:00Z", end_str="2026-04-01T00:00:00Z")
    assert start.month == 3
    assert end_dt.month == 4
