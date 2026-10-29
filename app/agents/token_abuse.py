"""Token Abuse Agent (P5): Flags session or token reuse from new places or after logout."""
from datetime import timedelta
import pandas as pd

from app.agents.base import Agent
from app.config import MITRE_BY_PATTERN
from app.models import Signal


class TokenAbuseAgent(Agent):
    name: str = "token_abuse"
    pattern: str = "P5"

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        if events is None or events.empty:
            return signals

        df = events.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        df = df.sort_values("timestamp")

        # Track logout times per identity
        logouts: dict[str, list[tuple[pd.Timestamp, str]]] = {}
        for _, row in df.iterrows():
            if row["action"] == "user.session.end":
                ident = str(row["identity_id"])
                logouts.setdefault(ident, []).append((row["timestamp"], str(row["event_id"])))

        token_first_ip: dict[str, str] = {}
        token_recent_calls: dict[str, list[dict]] = {}
        session_agents: dict[str, tuple[str, str]] = {}  # session_id -> (first_ua, event_id)

        five_minutes = timedelta(minutes=5)

        for _, row in df.iterrows():
            ident = str(row["identity_id"])
            token = str(row["token_id"]) if pd.notna(row["token_id"]) and row["token_id"] else None
            ip = str(row["src_ip"]) if pd.notna(row["src_ip"]) and row["src_ip"] else None
            ua = str(row["user_agent"]) if pd.notna(row["user_agent"]) and row["user_agent"] else None
            sess = str(row["session_id"]) if pd.notna(row["session_id"]) and row["session_id"] else None
            eid = str(row["event_id"])
            ts = row["timestamp"]

            # 1. Use after logout
            ident_logouts = logouts.get(ident, [])
            for logout_t, logout_eid in ident_logouts:
                if ts > logout_t and (ts - logout_t) < timedelta(hours=24):
                    signals.append(Signal(
                        pattern=self.pattern,
                        severity=0.9,
                        identity_id=ident,
                        session_id=sess,
                        agent=self.name,
                        reason=f"Activity detected after user logout ({logout_t.strftime('%H:%M:%SZ')}).",
                        evidence_event_ids=[logout_eid, eid],
                        mitre=MITRE_BY_PATTERN.get(self.pattern, ["T1550", "T1539"]),
                        timestamp=ts,
                    ))
                    break

            # 2. Token IP checks
            if token and ip:
                first_ip = token_first_ip.setdefault(token, ip)

                # Check concurrent use from 2 different IPs within 5 minutes
                recents = token_recent_calls.setdefault(token, [])
                concurrent_flagged = False
                for prev in recents:
                    if prev["ip"] != ip and (ts - prev["time"]) <= five_minutes:
                        signals.append(Signal(
                            pattern=self.pattern,
                            severity=0.9,
                            identity_id=ident,
                            session_id=sess,
                            agent=self.name,
                            reason=f"Token '{token}' used concurrently from {prev['ip']} and {ip} within 5 minutes.",
                            evidence_event_ids=[prev["event_id"], eid],
                            mitre=MITRE_BY_PATTERN.get(self.pattern, ["T1550", "T1539"]),
                            timestamp=ts,
                        ))
                        concurrent_flagged = True
                        break

                recents.append({"time": ts, "ip": ip, "event_id": eid})
                # keep recents short
                token_recent_calls[token] = [r for r in recents if (ts - r["time"]) <= five_minutes]

                if not concurrent_flagged and ip != first_ip:
                    signals.append(Signal(
                        pattern=self.pattern,
                        severity=0.6,
                        identity_id=ident,
                        session_id=sess,
                        agent=self.name,
                        reason=f"Token '{token}' used from new IP {ip} (first seen from {first_ip}).",
                        evidence_event_ids=[eid],
                        mitre=MITRE_BY_PATTERN.get(self.pattern, ["T1550", "T1539"]),
                        timestamp=ts,
                    ))

            # 3. User-Agent change within a session (for same source: okta or cloudtrail)
            if sess and ua:
                ua_key = (sess, str(row["source"]))
                if ua_key not in session_agents:
                    session_agents[ua_key] = (ua, eid)
                else:
                    first_ua, first_eid = session_agents[ua_key]
                    if ua != first_ua:
                        signals.append(Signal(
                            pattern=self.pattern,
                            severity=0.6,
                            identity_id=ident,
                            session_id=sess,
                            agent=self.name,
                            reason=f"User-Agent changed mid-session from '{first_ua[:30]}' to '{ua[:30]}'.",
                            evidence_event_ids=[first_eid, eid],
                            mitre=MITRE_BY_PATTERN.get(self.pattern, ["T1550", "T1539"]),
                            timestamp=ts,
                        ))

        return signals
