import pytest
from datetime import datetime, timezone
import pandas as pd

from app import store
from app.decision.feedback import apply_feedback
from app.decision.respond import apply_action, recommend
from app.decision.scoring import counterfactuals, decayed, score_session
from app.models import Alert, Prediction, Signal
from app.simulator.mock import MockSimulator
from app.utils import to_band


def test_bands():
    assert [to_band(x) for x in (39.9, 40, 69.9, 70, 89.9, 90)] == [
        "monitor", "step_up", "step_up", "restrict", "restrict", "revoke"
    ]


def test_pattern_combo_increases_risk():
    w = store.get_weights()
    sig1 = Signal(pattern="P1", severity=0.8, identity_id="u1", agent="a", reason="r",
                  evidence_event_ids=["e1"], timestamp=datetime.now(timezone.utc))
    sig2 = Signal(pattern="P2", severity=0.8, identity_id="u1", agent="a", reason="r",
                  evidence_event_ids=["e2"], timestamp=datetime.now(timezone.utc))

    r1, _ = score_session([sig1], None, w)
    r2, _ = score_session([sig1, sig2], None, w)
    assert r2 > r1


def test_decay():
    risk = 80.0
    half = decayed(risk, hours=6.0, confirmed=False)
    assert abs(half - 40.0) < 0.5
    # Confirmed does not decay
    assert decayed(risk, hours=6.0, confirmed=True) == 80.0


def test_revoke_without_approval_fails():
    store.init_db()
    sim = MockSimulator()
    alert = Alert(
        alert_id="AL-REVOKE-TEST",
        identity_id="u-revoke",
        risk=95.0,
        confidence=0.9,
        band="revoke",
        patterns=["P3"],
        mitre=["T1098"],
        reasons=["Escalation chain"],
        evidence_event_ids=["e1"],
        recommended_action="revoke",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    with pytest.raises(PermissionError):
        apply_action(alert, "revoke", approved_by=None, sim=sim)

    # With approval it works
    res = apply_action(alert, "revoke", approved_by="analyst-alice", sim=sim)
    assert res.status == "applied"
    assert res.detail == "simulated:revoke:ok"


def test_feedback_increases_weight():
    store.init_db()
    alert = Alert(
        alert_id="AL-FB-TEST",
        identity_id="u-fb",
        risk=80.0,
        confidence=0.8,
        band="restrict",
        patterns=["P1"],
        mitre=["T1078"],
        reasons=["Travel"],
        evidence_event_ids=["e1"],
        recommended_action="restrict",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    w_before = store.get_weights()["P1"]
    w_after = apply_feedback(alert, "tp")["P1"]
    assert w_after > w_before
