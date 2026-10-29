"""Dormant Account Agent (P2): Flags accounts waking up after a long silence."""
from datetime import timedelta
import pandas as pd

from app.agents.base import Agent
from app.config import DORMANT_DAYS, MITRE_BY_PATTERN
from app.models import Signal


class DormantAccountAgent(Agent):
    name: str = "dormant"
    pattern: str = "P2"

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        if events is None or events.empty:
            return signals

        df = events.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        df = df.sort_values("timestamp")

        dormant_thresh = timedelta(days=DORMANT_DAYS)

        for ident, group in df.groupby("identity_id"):
            prev_time = None
            prev_eid = None
            for _, row in group.iterrows():
                cur_time = row["timestamp"]
                outcome = str(row.get("outcome", "success")).lower()
                if prev_time is not None:
                    gap = cur_time - prev_time
                    if gap >= dormant_thresh and outcome == "success":
                        days_silent = int(gap.total_seconds() // 86400)
                        priv = int(row.get("privilege_level") or 1)
                        severity = 0.9 if priv >= 4 else 0.6
                        reason = f"Account inactive for {days_silent} days before this activity."
                        evidence = [str(prev_eid), str(row["event_id"])] if prev_eid else [str(row["event_id"])]

                        signals.append(Signal(
                            pattern=self.pattern,
                            severity=severity,
                            identity_id=str(ident),
                            session_id=row.get("session_id"),
                            agent=self.name,
                            reason=reason,
                            evidence_event_ids=evidence,
                            mitre=MITRE_BY_PATTERN.get(self.pattern, ["T1078.004"]),
                            timestamp=cur_time,
                        ))
                prev_time = cur_time
                prev_eid = row["event_id"]

        return signals
