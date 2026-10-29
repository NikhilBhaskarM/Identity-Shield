"""Enrichment module adding privilege, sensitivity, and location inference to events."""
import logging
import pandas as pd

from app.models import Source

log = logging.getLogger(__name__)


def _infer_privilege(identity_id: str, metadata: dict) -> int:
    ident_str = str(identity_id).lower()
    if ident_str in metadata:
        meta = metadata[ident_str]
        if "privilege_level" in meta:
            try:
                return int(meta["privilege_level"])
            except (ValueError, TypeError):
                pass
    if "admin" in ident_str or "root" in ident_str:
        return 5
    if "power" in ident_str or "ops" in ident_str or "dev" in ident_str:
        return 3
    return 1


def _infer_sensitivity(action: str, resource: str | None) -> int:
    act = str(action or "").lower()
    res = str(resource or "").lower()
    if any(k in act or k in res for k in ("iam", "secret", "kms", "cloudtrail")):
        return 5
    if any(k in res for k in ("finance", "secret", "prod", "backup")):
        return 4
    if resource:
        return 2
    return 1


def enrich(df: pd.DataFrame, metadata: dict) -> pd.DataFrame:
    if df is None or df.empty:
        return df

    out = df.copy()

    # Privilege level
    priv_map = {ident: _infer_privilege(ident, metadata) for ident in out["identity_id"].unique()}
    out["privilege_level"] = out["identity_id"].map(priv_map).fillna(1).astype(int)

    # Resource sensitivity
    sensitivities = [
        _infer_sensitivity(a, r) for a, r in zip(out["action"], out["resource"])
    ]
    out["resource_sensitivity"] = sensitivities

    # Location enrichment for CloudTrail events using Okta login context with same identity and IP
    try:
        okta_logins = out[
            (out["source"] == Source.okta)
            & (out["action"] == "user.session.start")
            & (out["src_ip"].notna())
            & (out["lat"].notna())
        ].copy()

        if not okta_logins.empty:
            lookup = {}
            for _, row in okta_logins.iterrows():
                key = (row["identity_id"], row["src_ip"])
                # Keep latest geo info
                lookup[key] = {
                    "lat": row["lat"],
                    "lon": row["lon"],
                    "country": row["country"],
                    "city": row["city"],
                    "asn": row["asn"],
                }

            # Fill missing geo fields
            for idx, row in out.iterrows():
                if row["source"] == Source.cloudtrail and (pd.isna(row["lat"]) or pd.isna(row["country"])):
                    geo = lookup.get((row["identity_id"], row["src_ip"]))
                    if geo:
                        out.at[idx, "lat"] = geo["lat"]
                        out.at[idx, "lon"] = geo["lon"]
                        out.at[idx, "country"] = geo["country"]
                        out.at[idx, "city"] = geo["city"]
                        if pd.isna(row["asn"]):
                            out.at[idx, "asn"] = geo["asn"]
    except Exception:
        log.exception("Geo enrichment failed")

    return out
