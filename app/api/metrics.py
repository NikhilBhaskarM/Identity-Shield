"""Metrics and scoring weights API routes."""
from fastapi import APIRouter, Request

from app import store
from app.models import Metrics
from app.utils import clean_json

router = APIRouter(tags=["metrics"])


@router.get("/metrics", response_model=Metrics)
def get_metrics(request: Request):
    res = getattr(request.app.state, "result", None)
    if res is None or res.metrics is None:
        return Metrics()
    return res.metrics


@router.get("/weights")
def get_weights():
    return clean_json(store.get_weights())
