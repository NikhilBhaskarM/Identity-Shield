"""Impossible Travel Agent (P1): Flags logins too far apart for the time between them."""
from datetime import timedelta
import pandas as pd

from app.agents.base import Agent
from app.config import IMPOSSIBLE_TRAVEL_KMH, MITRE_BY_PATTERN
from app.models import Category, Signal
from app.utils import haversine_km


class ImpossibleTravelAgent(Agent):
    name: str = "impossible_travel"
    pattern: str = "P1"

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        if events is None or events.empty:
            return signals

        # Filter: auth, success, lat/lon present
        sub = events[
            (events["category"] == Category.auth)
            & (events["outcome"] == "success")
            & (events["lat"].notna())
            & (events["lon"].notna())
        ].copy()

        if sub.empty:
            return signals

        sub["timestamp"] = pd.to_datetime(sub["timestamp"], utc=True)
        sub = sub.sort_values("timestamp")

        for ident, group in sub.groupby("identity_id"):
            prev_row = None
            for _, row in group.iterrows():
                if prev_row is not None:
                    t_diff = (row["timestamp"] - prev_row["timestamp"]).total_seconds()
                    hours = max(t_diff / 3600.0, 0.001)
                    if hours >= 0:
                        dist_km = haversine_km(
                            float(prev_row["lat"]), float(prev_row["lon"]),
                            float(row["lat"]), float(row["lon"])
                        )
                        speed = dist_km / hours
                        # Flag if speed exceeds threshold and ASN or location differs
                        asn_differs = str(prev_row.get("asn")) != str(row.get("asn"))
                        loc_differs = dist_km > 50.0

                        if speed > IMPOSSIBLE_TRAVEL_KMH and (asn_differs or loc_differs):
                            severity = min(1.0, max(0.4, speed / 3000.0))
                            minutes = max(t_diff / 60.0, 1.0)
                            c1 = prev_row.get("city") or prev_row.get("country") or "previous location"
                            c2 = row.get("city") or row.get("country") or "unknown"
                            reason = (
                                f"Login from {c2}, {dist_km:,.0f} km from {c1}, "
                                f"{minutes:.0f} min after previous login ({speed:,.0f} km/h)."
                            )
                            signals.append(Signal(
                                pattern=self.pattern,
                                severity=round(severity, 2),
                                identity_id=str(ident),
                                session_id=row.get("session_id"),
                                agent=self.name,
                                reason=reason,
                                evidence_event_ids=[str(prev_row["event_id"]), str(row["event_id"])],
                                mitre=MITRE_BY_PATTERN.get(self.pattern, ["T1078"]),
                                timestamp=row["timestamp"],
                            ))
                prev_row = row

        return signals
