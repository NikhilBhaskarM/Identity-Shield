"""Explanation module generating reasons, MITRE tags, and evidence lists."""
import pandas as pd

from app.models import Signal


def build_reasons(signals: list[Signal]) -> list[str]:
    if not signals:
        return []
    sorted_sigs = sorted(signals, key=lambda s: s.severity, reverse=True)
    reasons: list[str] = []
    seen = set()
    for s in sorted_sigs:
        if s.reason and s.reason not in seen:
            seen.add(s.reason)
            reasons.append(s.reason)
    return reasons


def mitre_tags(signals: list[Signal]) -> list[str]:
    tags: set[str] = set()
    for s in (signals or []):
        for m in (s.mitre or []):
            if m:
                tags.add(m)
    return sorted(list(tags))


def evidence_ids(signals: list[Signal], events: pd.DataFrame | None = None) -> list[str]:
    raw_ids: set[str] = set()
    for s in (signals or []):
        for eid in (s.evidence_event_ids or []):
            if eid:
                raw_ids.add(eid)

    if not raw_ids:
        return []

    if events is not None and not events.empty and "event_id" in events.columns:
        # Order by event timestamp
        sub = events[events["event_id"].isin(raw_ids)]
        if not sub.empty:
            sub = sub.sort_values("timestamp")
            return [str(e) for e in sub["event_id"].unique()]

    return sorted(list(raw_ids))
