"""Alerts API router."""
from fastapi import APIRouter, HTTPException, Request

from app import store
from app.decision.feedback import apply_feedback
from app.decision.respond import apply_action
from app.decision.scoring import counterfactuals, score_session
from app.models import ActionRequest, ActionResult, Alert, Event, FeedbackRequest
from app.simulator import get_simulator
from app.utils import to_band

router = APIRouter(tags=["alerts"])


def _result(request: Request):
    res = getattr(request.app.state, "result", None)
    if res is None:
        raise HTTPException(status_code=503, detail="Pipeline has not produced results yet")
    return res


@router.get("/alerts", response_model=list[Alert])
def list_alerts(request: Request, min_risk: float = 0.0, band: str | None = None,
                pattern: str | None = None, identity: str | None = None,
                limit: int = 100, offset: int = 0):
    alerts = _result(request).alerts
    out = [
        a for a in alerts
        if a.risk >= min_risk
        and (band is None or a.band == band)
        and (pattern is None or pattern in a.patterns)
        and (identity is None or a.identity_id == identity)
    ]
    out.sort(key=lambda a: (a.risk, a.blast_radius), reverse=True)
    return out[offset: offset + max(1, min(limit, 500))]


@router.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str, request: Request):
    for a in _result(request).alerts:
        if a.alert_id == alert_id:
            return a
    db_alert = store.load_alert(alert_id)
    if db_alert:
        return db_alert
    raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")


@router.get("/alerts/{alert_id}/events", response_model=list[Event])
def get_alert_events(alert_id: str, request: Request):
    res = _result(request)
    target_alert = None
    for a in res.alerts:
        if a.alert_id == alert_id:
            target_alert = a
            break
    if target_alert is None:
        target_alert = store.load_alert(alert_id)
    if target_alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    if res.events is None or res.events.empty:
        return []

    eids = set(target_alert.evidence_event_ids)
    sub = res.events[res.events["event_id"].isin(eids)]
    if sub.empty:
        return []
    sub = sub.sort_values("timestamp")
    events_out: list[Event] = []
    for _, row in sub.iterrows():
        try:
            events_out.append(Event(**row.to_dict()))
        except Exception:
            pass
    return events_out


@router.post("/alerts/{alert_id}/action", response_model=ActionResult)
def take_action(alert_id: str, body: ActionRequest, request: Request):
    res = _result(request)
    alert = None
    for a in res.alerts:
        if a.alert_id == alert_id:
            alert = a
            break
    if alert is None:
        alert = store.load_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    sim = get_simulator()
    try:
        result = apply_action(alert, body.action, body.approved_by, sim)
        return result
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.post("/alerts/{alert_id}/feedback", response_model=Alert)
def give_feedback(alert_id: str, body: FeedbackRequest, request: Request):
    res = _result(request)
    alert = None
    for a in res.alerts:
        if a.alert_id == alert_id:
            alert = a
            break
    if alert is None:
        alert = store.load_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    try:
        new_weights = apply_feedback(alert, body.label)
        # Rescore alert
        events_df = res.events
        sess_events = (
            events_df[events_df["session_id"] == alert.session_id]
            if (events_df is not None and alert.session_id) else None
        )
        sess_sigs = [s for s in res.signals if s.session_id == alert.session_id]

        new_risk, new_conf = score_session(sess_sigs, sess_events, new_weights, alert.prediction)
        alert.risk = new_risk
        alert.confidence = new_conf
        alert.band = to_band(new_risk)
        alert.counterfactuals = counterfactuals(sess_sigs, sess_events, new_weights, alert.prediction)

        store.update_alert(alert)
        return alert
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
