"""Evaluation module computing detection metrics and comparing against SOC baseline."""
import logging
import pandas as pd
from app.models import Alert, Metrics, Signal

log = logging.getLogger(__name__)


def compute_metrics(events_df: pd.DataFrame, alerts: list[Alert], signals: list[Signal],
                    skipped: int = 0, detection_time_ms: float = 0.0) -> Metrics:
    total_events = len(events_df) if events_df is not None else 0
    total_alerts = len(alerts) if alerts is not None else 0

    if events_df is None or events_df.empty or "label" not in events_df.columns:
        return Metrics(
            total_events=total_events,
            total_alerts=total_alerts,
            skipped_records=skipped,
            median_latency_ms=round(detection_time_ms / max(1, total_events), 2)
        )

    # Truth labels
    def _is_malicious(val):
        if val is None or pd.isna(val):
            return False
        s = str(val).strip().lower()
        return s not in {"benign", "none", "", "nan"}

    is_mal = events_df["label"].map(_is_malicious)
    if not is_mal.any():
        return Metrics(
            total_events=total_events,
            total_alerts=total_alerts,
            skipped_records=skipped,
            median_latency_ms=round(detection_time_ms / max(1, total_events), 2)
        )

    malicious_event_ids = set(events_df.loc[is_mal, "event_id"])

    # Model predictions: events in alert evidence
    predicted_event_ids: set[str] = set()
    for a in alerts:
        predicted_event_ids.update(a.evidence_event_ids)

    tp = len(predicted_event_ids & malicious_event_ids)
    fp = len(predicted_event_ids - malicious_event_ids)
    fn = len(malicious_event_ids - predicted_event_ids)

    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

    # Session-level precision
    events_by_sess = events_df.groupby("session_id")
    malicious_sessions = set()
    for sess_id, grp in events_by_sess:
        if grp["event_id"].isin(malicious_event_ids).any():
            malicious_sessions.add(sess_id)

    correct_alert_sessions = sum(1 for a in alerts if a.session_id in malicious_sessions)
    session_prec = correct_alert_sessions / total_alerts if total_alerts > 0 else 0.0

    # Baseline: flags failed logins and IPs with >= 3 failures
    failures = events_df[events_df["outcome"] == "failure"]
    failed_ips = failures["src_ip"].value_counts()
    repeat_ips = set(failed_ips[failed_ips >= 3].index)

    baseline_flagged = set(
        events_df[
            (events_df["outcome"] == "failure")
            | (events_df["src_ip"].isin(repeat_ips))
        ]["event_id"]
    )
    b_tp = len(baseline_flagged & malicious_event_ids)
    b_fp = len(baseline_flagged - malicious_event_ids)
    b_fn = len(malicious_event_ids - baseline_flagged)
    b_prec = b_tp / (b_tp + b_fp) if (b_tp + b_fp) > 0 else 0.0
    b_rec = b_tp / (b_tp + b_fn) if (b_tp + b_fn) > 0 else 0.0
    b_f1 = (2 * b_prec * b_rec / (b_prec + b_rec)) if (b_prec + b_rec) > 0 else 0.0

    latency = round(detection_time_ms / max(1, total_events), 2)

    return Metrics(
        event_precision=round(prec, 3),
        event_recall=round(rec, 3),
        event_f1=round(f1, 3),
        session_precision=round(session_prec, 3),
        baseline_event_f1=round(b_f1, 3),
        median_latency_ms=latency,
        total_events=total_events,
        total_alerts=total_alerts,
        skipped_records=skipped,
    )
