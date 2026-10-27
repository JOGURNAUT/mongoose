from app.classify import classify_file_hash, classify_ip, classify_login
from app.models import AlertIn, AlertType, EnrichmentResult, Severity


def test_ip_high_confidence_is_high():
    enr = EnrichmentResult(source="abuseipdb", ok=True, data={"abuseConfidenceScore": 90, "totalReports": 40})
    result = classify_ip(enr)
    assert result.severity == Severity.high
    assert "90" in result.reasons[0]


def test_ip_low_confidence_is_low():
    enr = EnrichmentResult(source="abuseipdb", ok=True, data={"abuseConfidenceScore": 5, "totalReports": 1})
    assert classify_ip(enr).severity == Severity.low


def test_ip_enrichment_failure_is_unknown_not_low():
    """A failed lookup must never silently read as 'clean'."""
    enr = EnrichmentResult(source="abuseipdb", ok=False, error="timeout")
    result = classify_ip(enr)
    assert result.severity == Severity.unknown
    assert "timeout" in result.reasons[0]


def test_hash_high_ratio_is_high():
    enr = EnrichmentResult(source="virustotal", ok=True, data={"positives": 40, "total": 70})
    assert classify_file_hash(enr).severity == Severity.high


def test_hash_clean_is_low():
    enr = EnrichmentResult(source="virustotal", ok=True, data={"positives": 0, "total": 70})
    assert classify_file_hash(enr).severity == Severity.low


def test_hash_never_seen_is_unknown_not_low():
    """0 positives out of 0 total is 'no evidence', not 'clean' — must not be scored LOW."""
    enr = EnrichmentResult(source="virustotal", ok=True, data={"positives": 0, "total": 0})
    result = classify_file_hash(enr)
    assert result.severity == Severity.unknown


def test_login_brute_force_is_high():
    alert = AlertIn(type=AlertType.login, user="r.srivastava", failed_attempts_last_5min=8)
    result = classify_login(alert)
    assert result.severity == Severity.high
    assert "8 failed sign-ins" in result.reasons[0]


def test_login_impossible_travel_is_high():
    alert = AlertIn(
        type=AlertType.login,
        user="r.srivastava",
        country="RU",
        last_known_country="IN",
        minutes_since_last_login=12,
    )
    result = classify_login(alert)
    assert result.severity == Severity.high
    assert "not physically possible" in result.reasons[0]


def test_login_normal_pattern_is_low():
    alert = AlertIn(type=AlertType.login, user="r.srivastava", failed_attempts_last_5min=1)
    result = classify_login(alert)
    assert result.severity == Severity.low


def test_login_same_country_long_gap_is_not_flagged():
    alert = AlertIn(
        type=AlertType.login,
        user="r.srivastava",
        country="IN",
        last_known_country="IN",
        minutes_since_last_login=500,
    )
    assert classify_login(alert).severity == Severity.low
