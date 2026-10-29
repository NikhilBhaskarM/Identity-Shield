"""Tamper-evident audit log API routes."""
from fastapi import APIRouter

from app import audit
from app.models import AuditEntry
from app.utils import clean_json

router = APIRouter(tags=["audit"])


@router.get("/audit", response_model=list[AuditEntry])
def get_audit(limit: int = 200):
    return audit.list_entries(limit=limit)


@router.get("/audit/verify")
def verify_audit():
    valid, broken_at = audit.verify()
    return clean_json({"valid": valid, "broken_at": broken_at})
