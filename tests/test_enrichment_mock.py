"""MOCK_MODE is forced on in these tests (no API keys in the test env),
so these exercise the deterministic-mock path, not real network calls."""

import pytest

from app.enrichment import check_file_hash, check_ip


@pytest.mark.asyncio
async def test_mock_ip_is_deterministic():
    r1 = await check_ip("203.0.113.5")
    r2 = await check_ip("203.0.113.5")
    assert r1.data == r2.data
    assert r1.source == "mock"
    assert 0 <= r1.data["abuseConfidenceScore"] <= 100


@pytest.mark.asyncio
async def test_mock_different_ips_can_differ():
    r1 = await check_ip("203.0.113.5")
    r2 = await check_ip("198.51.100.9")
    # not a strict guarantee for every pair, but true for this fixed pair —
    # pins the hash-derived mock against silently degenerating to a constant
    assert r1.data != r2.data


@pytest.mark.asyncio
async def test_mock_file_hash_is_deterministic():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    r1 = await check_file_hash(h)
    r2 = await check_file_hash(h)
    assert r1.data == r2.data


@pytest.mark.asyncio
async def test_mock_file_hash_never_seen_bucket_is_reachable():
    """About 1 in 8 mock hashes land as total=0 ('never seen'), so the
    fail-closed UNKNOWN path is reachable end-to-end in mock mode, not just
    via the unit test that calls classify_file_hash() directly."""
    found_never_seen = False
    for i in range(32):
        result = await check_file_hash(f"probe-hash-{i}")
        if result.data["total"] == 0:
            found_never_seen = True
            assert result.data["positives"] == 0
            break
    assert found_never_seen, "no 'never seen' (total=0) hash found in 32 probes — bucket may be broken"
