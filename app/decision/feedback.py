"""Analyst feedback loop tuning detector weights online."""
import logging

from app import audit, config, store
from app.models import Alert

log = logging.getLogger(__name__)


def apply_feedback(alert: Alert, label: str) -> dict[str, float]:
    clean_lbl = str(label).strip().lower()
    if clean_lbl not in {"tp", "fp"}:
        raise ValueError("Feedback label must be 'tp' or 'fp'")

    target = 1.0 if clean_lbl == "tp" else 0.0
    predicted = float(alert.risk) / 100.0
    weights = store.get_weights()

    lr = config.FEEDBACK_LEARNING_RATE
    delta = lr * (target - predicted) * 10.0

    for p in alert.patterns:
        current_w = float(weights.get(p, config.SIGNAL_WEIGHTS.get(p, 20.0)))
        new_w = min(config.WEIGHT_MAX, max(config.WEIGHT_MIN, current_w + delta))
        store.set_weight(p, round(new_w, 2))

    alert.feedback = clean_lbl
    store.update_alert(alert)
    audit.append("feedback", f"feedback_{clean_lbl}", f"Alert {alert.alert_id} labeled {clean_lbl}")

    return store.get_weights()
