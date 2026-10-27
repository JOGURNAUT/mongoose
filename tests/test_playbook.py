from app.models import Severity
from app.playbook import build_playbook


def test_high_severity_pages_oncall():
    result = build_playbook(Severity.high)
    assert any("on-call" in a for a in result.actions)
    assert result.fail_closed is False


def test_unknown_fails_closed_not_cleared():
    result = build_playbook(Severity.unknown)
    assert result.fail_closed is True
    assert any("FAIL CLOSED" in a for a in result.actions)
    # must not suggest closing the alert with no action
    assert not any(a == "No immediate action required" for a in result.actions)


def test_low_severity_closes_quietly():
    result = build_playbook(Severity.low)
    assert result.fail_closed is False
    assert any("close" in a.lower() for a in result.actions)
