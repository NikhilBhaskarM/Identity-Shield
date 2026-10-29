"""Privilege Escalation Agent (P3): Reconstructs multi-step escalation chains."""
from datetime import timedelta
import pandas as pd

from app.agents.base import Agent
from app.config import ESCALATION_WINDOW_HOURS, MITRE_BY_PATTERN
from app.models import ChainStep, Signal

STATE_OF_ACTION = {
    "ListUsers": "Recon", "ListRoles": "Recon", "ListPolicies": "Recon",
    "GetAccountAuthorizationDetails": "Recon",
    "CreateAccessKey": "CredCreate", "CreateLoginProfile": "CredCreate",
    "UpdateLoginProfile": "CredCreate",
    "CreateUser": "IdentityCreate", "CreateRole": "IdentityCreate",
    "AttachUserPolicy": "PermGrant", "AttachRolePolicy": "PermGrant",
    "PutUserPolicy": "PermGrant", "PutRolePolicy": "PermGrant",
    "AddUserToGroup": "PermGrant",
    "UpdateAssumeRolePolicy": "TrustChange",
    "AssumeRole": "RoleAssume", "PassRole": "RoleAssume",
    "GetSecretValue": "Impact", "StopLogging": "Impact", "DeleteTrail": "Impact",
}
ESCALATION_ORDER = ["Recon", "CredCreate", "IdentityCreate", "PermGrant",
                    "TrustChange", "RoleAssume", "Impact"]


class PrivEscalationAgent(Agent):
    name: str = "priv_escalation"
    pattern: str = "P3"

    def __init__(self) -> None:
        super().__init__()
        self.last_chains: dict[str, list[ChainStep]] = {}

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        self.last_chains = {}
        if events is None or events.empty:
            return signals

        df = events.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        df = df.sort_values("timestamp")

        window = timedelta(hours=ESCALATION_WINDOW_HOURS)

        for ident, group in df.groupby("identity_id"):
            relevant: list[dict] = []
            for _, row in group.iterrows():
                act = str(row["action"])
                state = STATE_OF_ACTION.get(act)
                if state:
                    relevant.append({
                        "event_id": str(row["event_id"]),
                        "action": act,
                        "state": state,
                        "timestamp": row["timestamp"],
                        "session_id": row.get("session_id"),
                    })

            if len(relevant) < 2:
                continue

            # Sliding window of 6 hours
            for i in range(len(relevant)):
                steps: list[ChainStep] = []
                seen_states = set()
                t_start = relevant[i]["timestamp"]

                for j in range(i, len(relevant)):
                    curr = relevant[j]
                    if curr["timestamp"] - t_start > window:
                        break

                    steps.append(ChainStep(
                        event_id=curr["event_id"],
                        action=curr["action"],
                        state=curr["state"],
                        timestamp=curr["timestamp"]
                    ))
                    seen_states.add(curr["state"])

                non_recon_states = seen_states - {"Recon"}
                if len(seen_states) >= 2 and len(non_recon_states) >= 2:
                    actions = [s.action for s in steps]
                    reason = f"Escalation chain: {' -> '.join(actions)}."
                    severity = min(1.0, 0.4 + 0.15 * len(seen_states))
                    last_item = relevant[min(j, len(relevant) - 1)]
                    target_sess = last_item.get("session_id") or f"chain-{ident}"
                    self.last_chains[target_sess] = steps

                    signals.append(Signal(
                        pattern=self.pattern,
                        severity=round(severity, 2),
                        identity_id=str(ident),
                        session_id=target_sess,
                        agent=self.name,
                        reason=reason,
                        evidence_event_ids=[s.event_id for s in steps],
                        mitre=MITRE_BY_PATTERN.get(self.pattern, ["T1098", "T1548"]),
                        timestamp=steps[-1].timestamp,
                    ))
                    break  # Don't duplicate chain signals for the same window

        return signals
