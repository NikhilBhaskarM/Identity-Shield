"""Health, summary, and pipeline trigger API routes."""
from collections import Counter
from typing import Optional
from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.config import PATTERN_NAMES
from app.models import Health
from app.pipeline import get_identity_rows, run_pipeline
from app.utils import clean_json

router = APIRouter(tags=["health"])


class PipelineRunRequest(BaseModel):
    use_sample: Optional[bool] = None


@router.get("/health", response_model=Health)
def get_health(request: Request):
    res = getattr(request.app.state, "result", None)
    if res is None:
        from app.main import get_or_run_pipeline
        res = get_or_run_pipeline(request.app)
    err = getattr(request.app.state, "startup_error", "")
    if res is None:
        return Health(
            status="error" if err else "ok",
            pipeline="failed" if err else "not_run",
            detail=err or "Pipeline not yet initialized",
            data_mode="none",
            events=0,
            alerts=0,
        )
    return Health(
        status="ok",
        pipeline=res.status,
        detail=res.detail,
        data_mode=res.data_mode,
        events=len(res.events) if res.events is not None else 0,
        alerts=len(res.alerts) if res.alerts is not None else 0,
    )


@router.post("/pipeline/run", response_model=Health)
def trigger_pipeline(request: Request, body: Optional[PipelineRunRequest] = None):
    use_sample = body.use_sample if body else None
    result = run_pipeline(use_sample=use_sample)
    request.app.state.result = result
    request.app.state.startup_error = "" if result.status == "ok" else result.detail
    return get_health(request)


@router.get("/summary")
def get_summary(request: Request):
    res = getattr(request.app.state, "result", None)
    if res is None:
        from app.main import get_or_run_pipeline
        res = get_or_run_pipeline(request.app)
    if res is None:
        return clean_json({
            "by_band": {"monitor": 0, "step_up": 0, "restrict": 0, "revoke": 0},
            "by_pattern": {p: 0 for p in PATTERN_NAMES},
            "top_identities": [],
            "totals": {"events": 0, "alerts": 0, "identities": 0},
        })

    alerts = res.alerts or []
    band_counts = Counter(a.band for a in alerts)
    by_band = {
        "monitor": band_counts.get("monitor", 0),
        "step_up": band_counts.get("step_up", 0),
        "restrict": band_counts.get("restrict", 0),
        "revoke": band_counts.get("revoke", 0),
    }

    pat_counts = Counter()
    for a in alerts:
        for p in a.patterns:
            pat_counts[p] += 1
    by_pattern = {p: pat_counts.get(p, 0) for p in PATTERN_NAMES}

    ident_rows = get_identity_rows(res)
    top_identities = ident_rows[:5]

    totals = {
        "events": len(res.events) if res.events is not None else 0,
        "alerts": len(alerts),
        "identities": len(ident_rows),
    }

    return clean_json({
        "by_band": by_band,
        "by_pattern": by_pattern,
        "top_identities": top_identities,
        "totals": totals,
    })
