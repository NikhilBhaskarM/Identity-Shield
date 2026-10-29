"""Identities, graph, timeline, and hygiene API routes."""
from datetime import timedelta
from fastapi import APIRouter, HTTPException, Request
import pandas as pd

from app.config import DORMANT_DAYS
from app.correlate.graph import escalation_paths, identity_subgraph
from app.models import Event, IdentityGraph, Signal
from app.pipeline import get_identity_rows
from app.utils import clean_json

router = APIRouter(tags=["identities"])


def _result(request: Request):
    res = getattr(request.app.state, "result", None)
    if res is None:
        raise HTTPException(status_code=503, detail="Pipeline has not produced results yet")
    return res


@router.get("/identities")
def list_identities(request: Request, min_risk: float = 0.0):
    res = _result(request)
    rows = get_identity_rows(res)
    filtered = [r for r in rows if r["risk"] >= min_risk]
    return clean_json(filtered)


@router.get("/identities/{identity_id}/graph", response_model=IdentityGraph)
def get_identity_graph(identity_id: str, request: Request):
    res = _result(request)
    if res.graph is None or not res.graph.has_node(f"user:{identity_id}"):
        raise HTTPException(status_code=404, detail=f"Identity {identity_id} not found in graph")

    suspicious_ids = set()
    for a in res.alerts:
        if a.identity_id == identity_id:
            suspicious_ids.update(a.evidence_event_ids)

    return identity_subgraph(res.graph, identity_id, suspicious_ids)


@router.get("/sessions/{session_id}/timeline")
def get_session_timeline(session_id: str, request: Request):
    res = _result(request)
    if res.events is None or res.events.empty:
        raise HTTPException(status_code=404, detail="No events available")

    sub = res.events[res.events["session_id"] == session_id]
    if sub.empty:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    sub = sub.sort_values("timestamp")
    sess_sigs = [s for s in res.signals if s.session_id == session_id]

    items = []
    for _, row in sub.iterrows():
        eid = str(row["event_id"])
        ev_dict = row.to_dict()
        matching_sigs = [s for s in sess_sigs if eid in s.evidence_event_ids]
        items.append({
            "event": Event(**ev_dict),
            "signals": matching_sigs,
        })

    return clean_json(items)


@router.get("/hygiene")
def get_hygiene(request: Request):
    res = _result(request)
    dormant_admins = []

    if res.events is not None and not res.events.empty:
        df = res.events.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        dormant_thresh = timedelta(days=DORMANT_DAYS)

        for ident, grp in df.groupby("identity_id"):
            priv = int(grp["privilege_level"].max() if "privilege_level" in grp else 1)
            if priv >= 4:
                grp_sorted = grp.sort_values("timestamp")
                prev_t = None
                for _, row in grp_sorted.iterrows():
                    cur_t = row["timestamp"]
                    if prev_t is not None and (cur_t - prev_t) >= dormant_thresh:
                        days = int((cur_t - prev_t).total_seconds() // 86400)
                        dormant_admins.append({
                            "identity_id": ident,
                            "privilege_level": priv,
                            "days_inactive": days,
                            "reactivated_at": cur_t.isoformat(),
                        })
                    prev_t = cur_t

    # Escalation paths for top risky identities
    ident_rows = get_identity_rows(res)
    top_idents = [r["identity_id"] for r in ident_rows[:10]]
    paths_out = []
    if res.graph is not None:
        for ident in top_idents:
            paths = escalation_paths(res.graph, ident)
            if paths:
                paths_out.append({
                    "identity_id": ident,
                    "paths": paths,
                })

    return clean_json({
        "dormant_admins": dormant_admins,
        "escalation_paths": paths_out,
    })
