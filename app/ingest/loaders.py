"""Loaders for CloudTrail, Okta, metadata and label files in various formats."""
import csv
import gzip
import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _open_file(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _read_records(path: Path) -> tuple[list[dict], int]:
    """Read a JSON/JSONL/CSV file safely; skip corrupt lines/records."""
    records: list[dict] = []
    skipped = 0
    try:
        suffix = path.suffix.lower()
        if suffix == ".gz":
            stem_suffix = Path(path.stem).suffix.lower()
        else:
            stem_suffix = suffix

        if stem_suffix == ".csv":
            with _open_file(path) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(dict(row))
            return records, skipped

        with _open_file(path) as f:
            content = f.read().strip()
            if not content:
                return records, skipped

            # Detect format by first non-space character
            if content.startswith("{"):
                try:
                    obj = json.loads(content)
                    if isinstance(obj, dict):
                        if "Records" in obj and isinstance(obj["Records"], list):
                            return obj["Records"], skipped
                        return [obj], skipped
                    elif isinstance(obj, list):
                        return obj, skipped
                except json.JSONDecodeError:
                    pass  # Might be JSON Lines with curly brace

            if content.startswith("["):
                try:
                    obj = json.loads(content)
                    if isinstance(obj, list):
                        return obj, skipped
                except json.JSONDecodeError:
                    pass

            # Try JSON Lines
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        records.append(item)
                    else:
                        skipped += 1
                except Exception:
                    skipped += 1

    except Exception:
        log.exception("Error reading file %s", path)
        skipped += 1

    return records, skipped


def load_cloudtrail(folder: Path | str) -> tuple[list[dict], int]:
    folder_path = Path(folder)
    if not folder_path.is_dir():
        return [], 0

    all_records: list[dict] = []
    total_skipped = 0

    files = sorted(list(folder_path.glob("**/*")))
    for path in files:
        if not path.is_file():
            continue
        name_lower = path.name.lower()
        # For sample dir or mixed dir: check name or content
        if "okta" in name_lower or "metadata" in name_lower or "label" in name_lower:
            continue
        recs, skipped = _read_records(path)
        all_records.extend(recs)
        total_skipped += skipped

    return all_records, total_skipped


def load_okta(folder: Path | str) -> tuple[list[dict], int]:
    folder_path = Path(folder)
    if not folder_path.is_dir():
        return [], 0

    all_records: list[dict] = []
    total_skipped = 0

    files = sorted(list(folder_path.glob("**/*")))
    for path in files:
        if not path.is_file():
            continue
        name_lower = path.name.lower()
        if "cloudtrail" in name_lower or "metadata" in name_lower or "label" in name_lower:
            continue
        # If in a dedicated okta folder, any file is okta; in mixed folder, require okta in name
        if "okta" not in str(folder_path).lower() and "okta" not in name_lower:
            continue
        recs, skipped = _read_records(path)
        all_records.extend(recs)
        total_skipped += skipped

    return all_records, total_skipped


def load_metadata(folder: Path | str) -> dict[str, dict]:
    folder_path = Path(folder)
    if not folder_path.is_dir():
        return {}

    metadata: dict[str, dict] = {}
    for path in sorted(list(folder_path.glob("**/*"))):
        if not path.is_file():
            continue
        if "metadata" not in path.name.lower() and folder_path.name != "metadata":
            continue
        recs, _ = _read_records(path)
        for r in recs:
            ident = r.get("identity_id") or r.get("id") or r.get("userName")
            if ident:
                metadata[str(ident).lower().strip()] = r
    return metadata


def load_labels(folder: Path | str) -> dict[str, str]:
    folder_path = Path(folder)
    if not folder_path.is_dir():
        return {}

    labels: dict[str, str] = {}
    for path in sorted(list(folder_path.glob("**/*"))):
        if not path.is_file():
            continue
        if "label" not in path.name.lower() and folder_path.name != "labels":
            continue
        recs, _ = _read_records(path)
        for r in recs:
            eid = r.get("event_id") or r.get("eventID") or r.get("uuid")
            lab = r.get("label") or r.get("attack_type")
            if eid and lab:
                labels[str(eid)] = str(lab)
    return labels
