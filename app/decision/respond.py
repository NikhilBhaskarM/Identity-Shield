"""Response recommendation, automated actions, and human-in-the-loop approvals."""
from datetime import datetime, timezone
import logging

from app import audit, config, store
from app.models import ActionResult, Alert
from app.simulator.base import SimulatorAdapter
from app.utils import to_band

log = logging.getLogger(__name__)

ALLOWED_ACTIONS = {"step_up", "restrict", "revoke", "dismiss", "monitor"}


def recommend(risk: float) -> str:
    band = to_band(risk)
    return band  # "monitor", "step_up", "restrict", "revoke"


def apply_action(alert: Alert, action: str, approved_by: str | None, sim: SimulatorAdapter) -> ActionResult:
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"Action '{action}' is not allowed. Allowed: {ALLOWED_ACTIONS}")

    if action == "revoke" and config.REQUIRE_APPROVAL_FOR_REVOKE and not approved_by:
        raise PermissionError("Revocation requires analyst approval")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if action == "step_up":
        used = store.friction_used(alert.identity_id, today)
        if used >= config.FRICTION_BUDGET_PER_DAY:
            status = "notified"
            detail = f"Friction budget exhausted ({used}/{config.FRICTION_BUDGET_PER_DAY}); notified admin instead"
        else:
            store.friction_increment(alert.identity_id, today)
            detail = sim.step_up(alert.identity_id, alert.session_id)
            status = "applied"
    elif action == "restrict":
        detail = sim.restrict(alert.identity_id, "temporary")
        status = "applied"
    elif action == "revoke":
        detail = sim.revoke(alert.identity_id, alert.session_id)
        status = "applied"
    elif action == "dismiss":
        detail = f"Alert dismissed by {approved_by or 'analyst'}"
        status = "dismissed"
    else:  # monitor
        detail = "Continuous monitoring active"
        status = "applied"

    alert.action_status = status
    store.update_alert(alert)
    audit.append("response", f"action_{action}", f"{alert.identity_id} ({alert.alert_id}): {status} - {detail}")

    return ActionResult(alert_id=alert.alert_id, action=action, status=status, detail=detail)


def auto_apply(alert: Alert, sim: SimulatorAdapter) -> Alert:
    rec = recommend(alert.risk)
    if rec == "revoke":
        alert.action_status = "pending"
    else:
        try:
            apply_action(alert, rec, approved_by="system", sim=sim)
        except Exception:
            log.exception("Auto apply action failed for alert %s", alert.alert_id)
            alert.action_status = "pending"
    return alert
