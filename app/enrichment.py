"""
Enrichment: look up what's known about an indicator (IP or file hash) before
deciding anything about it. Two real providers (AbuseIPDB, VirusTotal), and a
mock provider that stands in when no API key is configured, so the rest of
the pipeline can be built and tested without live keys.

Mock mode is deterministic, not random: it hashes the indicator itself, so
the same IP or hash always gets the same mock verdict across runs. That
matters for tests and demos — a flaky mock would make classification tests
flaky too.
"""

import hashlib
import logging

import httpx

from app.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, MOCK_MODE
from app.models import EnrichmentResult

logger = logging.getLogger("mongoose.enrichment")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/{file_hash}"


def _mock_score(indicator: str, buckets: int) -> int:
    """Deterministic 0..buckets-1 score derived from the indicator string."""
    digest = hashlib.sha256(indicator.encode()).hexdigest()
    return int(digest[:8], 16) % buckets


async def check_ip(source_ip: str) -> EnrichmentResult:
    if MOCK_MODE:
        logger.warning("MOCK MODE: ABUSEIPDB_API_KEY not set, using deterministic mock enrichment for %s", source_ip)
        score = _mock_score(source_ip, 101)  # 0..100, mirrors AbuseIPDB's own scale
        return EnrichmentResult(
            source="mock",
            ok=True,
            data={
                "abuseConfidenceScore": score,
                "totalReports": score // 5,
                "countryCode": "ZZ",
                "isp": "mock-isp",
            },
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                ABUSEIPDB_URL,
                params={"ipAddress": source_ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
        if resp.status_code != 200:
            return EnrichmentResult(source="abuseipdb", ok=False, error=f"HTTP {resp.status_code}: {resp.text[:200]}")
        payload = resp.json().get("data", {})
        return EnrichmentResult(
            source="abuseipdb",
            ok=True,
            data={
                "abuseConfidenceScore": payload.get("abuseConfidenceScore", 0),
                "totalReports": payload.get("totalReports", 0),
                "countryCode": payload.get("countryCode"),
                "isp": payload.get("isp"),
            },
        )
    except httpx.HTTPError as exc:
        logger.error("AbuseIPDB lookup failed for %s: %s", source_ip, exc)
        return EnrichmentResult(source="abuseipdb", ok=False, error=str(exc))


async def check_file_hash(file_hash: str) -> EnrichmentResult:
    if MOCK_MODE:
        logger.warning("MOCK MODE: VIRUSTOTAL_API_KEY not set, using deterministic mock enrichment for %s", file_hash)
        # 1-in-8 mock hashes land as "never seen" (total=0), so the fail-closed
        # UNKNOWN path is actually reachable via the live API in mock mode too,
        # not just in the unit test that calls classify_file_hash() directly.
        if _mock_score(file_hash, 8) == 0:
            return EnrichmentResult(source="mock", ok=True, data={"positives": 0, "total": 0})
        total = 70
        positives = _mock_score(file_hash, total + 1)  # 0..70
        return EnrichmentResult(
            source="mock",
            ok=True,
            data={"positives": positives, "total": total},
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                VIRUSTOTAL_URL.format(file_hash=file_hash),
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
            )
        if resp.status_code == 404:
            return EnrichmentResult(source="virustotal", ok=True, data={"positives": 0, "total": 0, "unseen": True})
        if resp.status_code != 200:
            return EnrichmentResult(source="virustotal", ok=False, error=f"HTTP {resp.status_code}: {resp.text[:200]}")
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        return EnrichmentResult(source="virustotal", ok=True, data={"positives": positives, "total": total})
    except httpx.HTTPError as exc:
        logger.error("VirusTotal lookup failed for %s: %s", file_hash, exc)
        return EnrichmentResult(source="virustotal", ok=False, error=str(exc))
