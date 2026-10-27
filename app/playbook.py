"""
Playbook: map a severity verdict to suggested response actions.

UNKNOWN fails closed, the same principle as OZi's release-sentinel design:
when the evidence needed to decide isn't available (enrichment down, hash
never seen before), the tool never quietly defaults to LOW. It escalates to
a human instead. A false "all clear" is worse than an analyst spending five
minutes on a false alarm.
"""

from app.models import PlaybookResult, Severity

_ACTIONS = {
    Severity.high: [
        "Isolate the affected host / block the source IP at the perimeter",
        "Page the on-call security engineer",
        "Open a P1 incident ticket with the enrichment evidence attached",
    ],
    Severity.medium: [
        "Flag for analyst review within the current shift",
        "Increase monitoring on the associated account or host for 24h",
    ],
    Severity.low: [
        "Log the alert and close",
        "No immediate action required",
    ],
}


def build_playbook(severity: Severity) -> PlaybookResult:
    if severity == Severity.unknown:
        return PlaybookResult(
            actions=[
                "FAIL CLOSED: evidence was insufficient to score this alert automatically",
                "Route to manual analyst review before closing",
                "Do not auto-clear — treat as at least MEDIUM until a human confirms otherwise",
            ],
            fail_closed=True,
        )
    return PlaybookResult(actions=_ACTIONS[severity], fail_closed=False)
