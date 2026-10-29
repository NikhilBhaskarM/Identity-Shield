"""API Anomaly Agent (P4): Flags rare, sensitive or new-region API calls."""
import pandas as pd

from app.agents.base import Agent
from app.config import API_RARITY_THRESHOLD, MITRE_BY_PATTERN, SENSITIVE_ACTIONS
from app.models import Category, Signal

try:
    from app.ml.peers import PeerModel
except ImportError:
    PeerModel = None


class ApiAnomalyAgent(Agent):
    name: str = "api_anomaly"
    pattern: str = "P4"

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        if events is None or events.empty:
            return signals

        # Only evaluate API calls
        df = events[events["category"] == Category.api].copy()
        if df.empty:
            return signals

        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        df = df.sort_values("timestamp")

        # Action counts per identity
        ident_counts = df.groupby("identity_id")["action"].value_counts()
        total_ident_counts = df.groupby("identity_id").size()

        seen_regions: dict[str, set[str]] = {}

        for _, row in df.iterrows():
            ident = str(row["identity_id"])
            act = str(row["action"])
            region = str(row["region"]) if pd.notna(row["region"]) else None
            eid = str(row["event_id"])
            sess = row.get("session_id")
            ts = row["timestamp"]

            is_sensitive = act in SENSITIVE_ACTIONS
            prior_regions = seen_regions.setdefault(ident, set())
            is_new_region = region is not None and region not in prior_regions and len(prior_regions) > 0
            if region:
                prior_regions.add(region)

            n_events = total_ident_counts.get(ident, 0)
            is_rare = False
            if n_events >= 5:
                act_count = ident_counts.get((ident, act), 0)
                rarity = 1.0 - (act_count / n_events)
                if rarity >= API_RARITY_THRESHOLD:
                    is_rare = True

            # Trigger condition: sensitive, or new region, or rare
            if is_sensitive or is_new_region or (is_rare and n_events >= 10):
                severity = 0.5
                reasons = []
                if is_sensitive:
                    severity += 0.3
                    reasons.append("sensitive action")
                if is_new_region:
                    severity += 0.2
                    reasons.append(f"new region '{region}'")
                if is_rare:
                    reasons.append("rarely performed action")

                severity = min(1.0, round(severity, 2))
                reason_str = f"Unusual API call '{act}': {', '.join(reasons)}."

                signals.append(Signal(
                    pattern=self.pattern,
                    severity=severity,
                    identity_id=ident,
                    session_id=sess,
                    agent=self.name,
                    reason=reason_str,
                    evidence_event_ids=[eid],
                    mitre=MITRE_BY_PATTERN.get(self.pattern, ["T1526", "T1562"]),
                    timestamp=ts,
                ))

        return signals
