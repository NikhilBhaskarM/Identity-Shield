"""Session correlation linking Okta sessions to AWS activity."""
from datetime import timedelta
import logging
import pandas as pd

from app.models import Source

log = logging.getLogger(__name__)


def assign_sessions(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df

    out = df.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], utc=True)
    out = out.sort_values("timestamp").reset_index(drop=True)

    # Track okta sessions: list of (start_time, identity_id, ip, session_id)
    okta_sessions: list[dict] = []
    session_ids: list[str] = [None] * len(out)

    for idx, row in out.iterrows():
        if row["source"] == Source.okta:
            raw_sess = row["session_id"]
            if raw_sess and not str(raw_sess).startswith("okta:"):
                sess_id = f"okta:{raw_sess}"
            elif raw_sess:
                sess_id = str(raw_sess)
            else:
                sess_id = f"okta:{row['event_id']}"
            session_ids[idx] = sess_id

            if row["action"] == "user.session.start":
                okta_sessions.append({
                    "time": row["timestamp"],
                    "identity_id": row["identity_id"],
                    "ip": row["src_ip"],
                    "session_id": sess_id,
                })

    # Link CloudTrail events to Okta sessions where possible
    twelve_hours = timedelta(hours=12)
    one_hour = timedelta(hours=1)

    # For grouping unlinked CloudTrail events by (identity_id, token_id) with 1h gap
    aws_session_counters: dict[tuple[str, str], int] = {}
    aws_last_time: dict[tuple[str, str], pd.Timestamp] = {}

    for idx, row in out.iterrows():
        if session_ids[idx] is not None:
            continue

        # Look for matching Okta session started within past 12h
        matched_sess = None
        cur_t = row["timestamp"]
        ident = row["identity_id"]
        ip = row["src_ip"]

        for s in reversed(okta_sessions):
            if s["identity_id"] == ident:
                gap = cur_t - s["time"]
                if timedelta(0) <= gap <= twelve_hours:
                    if ip and s["ip"] and ip == s["ip"]:
                        matched_sess = s["session_id"]
                        break
                    elif not matched_sess:
                        # Backup match if same identity within 12h
                        matched_sess = s["session_id"]

        if matched_sess:
            session_ids[idx] = matched_sess
        else:
            token = str(row["token_id"] or "default")
            key = (ident, token)
            last_t = aws_last_time.get(key)
            if last_t is None or (cur_t - last_t) > one_hour:
                aws_session_counters[key] = aws_session_counters.get(key, 0) + 1
            aws_last_time[key] = cur_t
            session_ids[idx] = f"aws:{ident}:{aws_session_counters[key]}"

    out["session_id"] = session_ids
    return out
