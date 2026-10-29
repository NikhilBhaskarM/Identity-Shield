"""Normalization module mapping CloudTrail and Okta logs into canonical Events."""
import logging
from typing import Any
import pandas as pd

from app.models import Category, Event, Source
from app.utils import dig, parse_ts

log = logging.getLogger(__name__)


def canonical_identity(value: str | None) -> str:
    """Normalize identity strings: lowercase, email -> local part, arn -> last segment."""
    if not value:
        return "unknown"
    val = str(value).strip().lower()
    if "@" in val:
        val = val.split("@")[0]
    elif "/" in val:
        val = val.split("/")[-1]
    return val or "unknown"


def _extract_ct_resource(rec: dict) -> str | None:
    resources = dig(rec, "resources")
    if isinstance(resources, list) and len(resources) > 0:
        first = resources[0]
        if isinstance(first, dict) and first.get("ARN"):
            return first["ARN"]
    req = dig(rec, "requestParameters")
    if isinstance(req, dict):
        for k in ("policyArn", "roleArn", "bucketName", "userName", "secretId", "name"):
            if req.get(k):
                return str(req[k])
    return None


def normalize_cloudtrail(rec: dict, idx: int) -> Event | None:
    ts = parse_ts(dig(rec, "eventTime") or dig(rec, "timestamp"))
    if ts is None:
        return None

    raw_id = (dig(rec, "userIdentity.userName")
              or dig(rec, "userIdentity.sessionContext.sessionIssuer.userName")
              or dig(rec, "userIdentity.arn")
              or dig(rec, "identity_id"))
    identity_id = canonical_identity(raw_id)

    action = str(dig(rec, "eventName") or dig(rec, "action", "Unknown"))
    if action in {"ConsoleLogin", "AssumeRoleWithSAML", "GetSessionToken"}:
        category = Category.auth
    else:
        category = Category.api

    outcome = "failure" if dig(rec, "errorCode") else "success"
    event_id = str(dig(rec, "eventID") or dig(rec, "event_id") or f"ct-{idx}")
    token_id = dig(rec, "userIdentity.accessKeyId") or dig(rec, "token_id")

    return Event(
        event_id=event_id,
        source=Source.cloudtrail,
        timestamp=ts,
        identity_id=identity_id,
        session_id=None,
        action=action,
        category=category,
        outcome=outcome,
        src_ip=dig(rec, "sourceIPAddress") or dig(rec, "src_ip"),
        user_agent=dig(rec, "userAgent") or dig(rec, "user_agent"),
        region=dig(rec, "awsRegion") or dig(rec, "region"),
        token_id=str(token_id) if token_id else None,
        resource=_extract_ct_resource(rec),
        resource_sensitivity=1,
        privilege_level=1,
        label=rec.get("label"),
    )


def normalize_okta(rec: dict, idx: int) -> Event | None:
    ts = parse_ts(dig(rec, "published") or dig(rec, "timestamp"))
    if ts is None:
        return None

    raw_id = dig(rec, "actor.alternateId") or dig(rec, "actor.id") or dig(rec, "identity_id")
    identity_id = canonical_identity(raw_id)

    event_type = str(dig(rec, "eventType") or dig(rec, "action", "unknown"))
    if event_type == "user.session.start" or event_type.startswith("user.authentication."):
        category = Category.auth
    elif event_type.startswith("user.session."):
        category = Category.session
    else:
        category = Category.api

    raw_res = dig(rec, "outcome.result") or dig(rec, "outcome", "success")
    outcome = "success" if str(raw_res).lower() == "success" else "failure"

    lat = dig(rec, "client.geographicalContext.geolocation.lat") or dig(rec, "lat")
    lon = dig(rec, "client.geographicalContext.geolocation.lon") or dig(rec, "lon")
    try:
        lat_f = float(lat) if lat is not None else None
    except (TypeError, ValueError):
        lat_f = None
    try:
        lon_f = float(lon) if lon is not None else None
    except (TypeError, ValueError):
        lon_f = None

    asn = dig(rec, "securityContext.asNumber") or dig(rec, "asn")
    asn_str = str(asn) if asn is not None else None

    raw_sess = dig(rec, "authenticationContext.externalSessionId") or dig(rec, "session_id")
    event_id = str(dig(rec, "uuid") or dig(rec, "event_id") or f"okta-{idx}")

    return Event(
        event_id=event_id,
        source=Source.okta,
        timestamp=ts,
        identity_id=identity_id,
        session_id=str(raw_sess) if raw_sess else None,
        action=event_type,
        category=category,
        outcome=outcome,
        src_ip=dig(rec, "client.ipAddress") or dig(rec, "src_ip"),
        country=dig(rec, "client.geographicalContext.country") or dig(rec, "country"),
        city=dig(rec, "client.geographicalContext.city") or dig(rec, "city"),
        lat=lat_f,
        lon=lon_f,
        asn=asn_str,
        user_agent=dig(rec, "client.userAgent.rawUserAgent") or dig(rec, "user_agent"),
        device_id=dig(rec, "client.device") or dig(rec, "debugContext.debugData.deviceFingerprint") or dig(rec, "device_id"),
        token_id=None,
        region=None,
        resource=None,
        resource_sensitivity=1,
        privilege_level=1,
        label=rec.get("label"),
    )


def normalize_all(ct: list[dict], okta: list[dict]) -> tuple[pd.DataFrame, int]:
    rows: list[dict] = []
    skipped = 0

    for idx, rec in enumerate(ct):
        try:
            ev = normalize_cloudtrail(rec, idx)
            if ev is not None:
                rows.append(ev.model_dump())
            else:
                skipped += 1
        except Exception:
            skipped += 1

    for idx, rec in enumerate(okta):
        try:
            ev = normalize_okta(rec, idx)
            if ev is not None:
                rows.append(ev.model_dump())
            else:
                skipped += 1
        except Exception:
            skipped += 1

    event_fields = list(Event.model_fields.keys())
    if not rows:
        return pd.DataFrame(columns=event_fields), skipped

    df = pd.DataFrame(rows, columns=event_fields)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df, skipped
