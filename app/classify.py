"""
Severity classification: deterministic rules over enrichment data and alert
context. No LLM here, on purpose — a severity verdict needs to be the same
every time for the same input, and auditable (reasons, not a vibe). This
mirrors the OZi release-sentinel design: deterministic stages decide,
anything advisory sits outside the decision path.

Every verdict carries its reasons as a list of plain-English evidence
strings, so a responder (or an interview panel) can see exactly why an
alert was scored the way it was, not just the final label.
"""

from app.models import AlertIn, AlertType, ClassificationResult, EnrichmentResult, Severity

# AbuseIPDB's own documentation treats a confidence score above 75 as a
# clear abuse signal and recommends blocking; 25 is their suggested floor
# for "worth a closer look" rather than outright blocking.
IP_HIGH_THRESHOLD = 75
IP_MEDIUM_THRESHOLD = 25

# VirusTotal community convention: >=30% engine detection is treated as
# high-confidence malicious; single-digit detections are common noise
# from engines with aggressive heuristics, so 5% is the floor worth a
# second look rather than an auto-dismiss.
HASH_HIGH_RATIO = 0.30
HASH_MEDIUM_RATIO = 0.05

# Same brute-force/impossible-travel thresholds as Meerkat's log-based
# rules (fail2ban-style 5-attempt default, no realistic-travel-time
# window under 60 min) — kept identical on purpose so the two tools
# agree on what "suspicious" means for the same underlying behavior.
BRUTE_FORCE_ATTEMPTS = 5
IMPOSSIBLE_TRAVEL_MINUTES = 60


def classify_ip(enrichment: EnrichmentResult) -> ClassificationResult:
    if not enrichment.ok:
        return ClassificationResult(
            severity=Severity.unknown,
            reasons=[f"enrichment failed ({enrichment.source}): {enrichment.error}"],
        )

    score = enrichment.data.get("abuseConfidenceScore", 0)
    reports = enrichment.data.get("totalReports", 0)
    reasons = [f"AbuseIPDB confidence score {score}/100 from {reports} report(s)"]

    if score >= IP_HIGH_THRESHOLD:
        return ClassificationResult(severity=Severity.high, reasons=reasons)
    if score >= IP_MEDIUM_THRESHOLD:
        return ClassificationResult(severity=Severity.medium, reasons=reasons)
    return ClassificationResult(severity=Severity.low, reasons=reasons)


def classify_file_hash(enrichment: EnrichmentResult) -> ClassificationResult:
    if not enrichment.ok:
        return ClassificationResult(
            severity=Severity.unknown,
            reasons=[f"enrichment failed ({enrichment.source}): {enrichment.error}"],
        )

    positives = enrichment.data.get("positives", 0)
    total = enrichment.data.get("total", 0)

    if total == 0:
        return ClassificationResult(
            severity=Severity.unknown,
            reasons=["file hash not seen by any scan engine yet (0/0) — insufficient evidence either way"],
        )

    ratio = positives / total
    reasons = [f"{positives}/{total} engines flagged this hash ({ratio:.0%})"]

    if ratio >= HASH_HIGH_RATIO:
        return ClassificationResult(severity=Severity.high, reasons=reasons)
    if ratio >= HASH_MEDIUM_RATIO:
        return ClassificationResult(severity=Severity.medium, reasons=reasons)
    return ClassificationResult(severity=Severity.low, reasons=reasons)


def classify_login(alert: AlertIn) -> ClassificationResult:
    reasons: list[str] = []
    severity = Severity.low

    attempts = alert.failed_attempts_last_5min or 0
    if attempts >= BRUTE_FORCE_ATTEMPTS:
        reasons.append(f"{attempts} failed sign-ins in the last 5 minutes (brute-force threshold is {BRUTE_FORCE_ATTEMPTS})")
        severity = Severity.high

    if (
        alert.country
        and alert.last_known_country
        and alert.country != alert.last_known_country
        and alert.minutes_since_last_login is not None
        and alert.minutes_since_last_login < IMPOSSIBLE_TRAVEL_MINUTES
    ):
        reasons.append(
            f"sign-in from {alert.country} only {alert.minutes_since_last_login:.0f} min after a sign-in "
            f"from {alert.last_known_country} — not physically possible, credential likely shared or stolen"
        )
        severity = Severity.high

    if not reasons:
        reasons.append("no brute-force or impossible-travel pattern matched")

    return ClassificationResult(severity=severity, reasons=reasons)


def classify(alert: AlertIn, enrichment: EnrichmentResult | None) -> ClassificationResult:
    if alert.type == AlertType.ip_traffic:
        assert enrichment is not None
        return classify_ip(enrichment)
    if alert.type == AlertType.file_hash:
        assert enrichment is not None
        return classify_file_hash(enrichment)
    if alert.type == AlertType.login:
        return classify_login(alert)
    raise ValueError(f"unhandled alert type: {alert.type}")
