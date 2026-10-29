"""Session feature extraction for anomaly detection and scoring."""
import logging
import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

IAM_WRITES = {
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "AddUserToGroup", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
    "CreateUser", "CreateRole", "UpdateAssumeRolePolicy",
}

NUMERIC_COLUMNS = [
    "n_events", "n_distinct_actions", "n_iam_writes", "max_sensitivity",
    "privilege_level", "n_ips", "n_user_agents", "failure_rate",
    "hour_deviation", "new_region_count", "duration_min", "events_per_min",
    "peer_rarity_mean"
]


def numeric_columns() -> list[str]:
    return list(NUMERIC_COLUMNS)


def session_features(df: pd.DataFrame, peer_model=None) -> pd.DataFrame:
    if df is None or df.empty:
        cols = ["identity_id"] + NUMERIC_COLUMNS
        return pd.DataFrame(columns=cols)

    events = df.copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True)
    events["hour"] = events["timestamp"].dt.hour

    # Identity median login hour
    ident_median_hour = events.groupby("identity_id")["hour"].median().to_dict()

    rows: list[dict] = []
    for sess_id, group in events.groupby("session_id"):
        ident = group["identity_id"].iloc[0]
        n_ev = len(group)
        n_act = group["action"].nunique()
        n_iam = sum(1 for a in group["action"] if a in IAM_WRITES)
        max_sens = float(group.get("resource_sensitivity", pd.Series([1])).max())
        priv = float(group.get("privilege_level", pd.Series([1])).max())
        n_ips = group["src_ip"].dropna().nunique()
        n_uas = group["user_agent"].dropna().nunique()

        n_fail = sum(1 for o in group["outcome"] if str(o).lower() == "failure")
        fail_rate = n_fail / n_ev if n_ev else 0.0

        med_h = ident_median_hour.get(ident, 12.0)
        h_dev = float(np.mean([abs(h - med_h) for h in group["hour"]])) if n_ev else 0.0

        regions = group["region"].dropna().unique()
        new_reg = len(regions)

        min_t = group["timestamp"].min()
        max_t = group["timestamp"].max()
        duration_min = max(0.0, (max_t - min_t).total_seconds() / 60.0)
        events_per_min = n_ev / max(duration_min, 1.0)

        if peer_model and hasattr(peer_model, "peer_rarity"):
            rarities = [peer_model.peer_rarity(ident, a) for a in group["action"]]
            peer_rarity_mean = float(np.mean(rarities)) if rarities else 0.0
        else:
            peer_rarity_mean = 0.0

        rows.append({
            "session_id": str(sess_id),
            "identity_id": str(ident),
            "n_events": float(n_ev),
            "n_distinct_actions": float(n_act),
            "n_iam_writes": float(n_iam),
            "max_sensitivity": float(max_sens),
            "privilege_level": float(priv),
            "n_ips": float(n_ips),
            "n_user_agents": float(n_uas),
            "failure_rate": float(fail_rate),
            "hour_deviation": float(h_dev),
            "new_region_count": float(new_reg),
            "duration_min": float(duration_min),
            "events_per_min": float(events_per_min),
            "peer_rarity_mean": float(peer_rarity_mean),
        })

    feat_df = pd.DataFrame(rows).set_index("session_id")
    for col in NUMERIC_COLUMNS:
        if col in feat_df.columns:
            feat_df[col] = feat_df[col].fillna(0.0).astype(float)
    return feat_df
