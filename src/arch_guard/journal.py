from __future__ import annotations

import json

from dataclasses import dataclass


@dataclass(slots=True)
class JournalRecord:
    message: str
    timestamp: float | None = None


def parse_journal_line(
    line: str,
) -> JournalRecord | None:

    try:
        obj = json.loads(line)
    except Exception:
        return None

    if not isinstance(obj, dict):
        return None

    message = obj.get("MESSAGE")

    if not isinstance(message, str):
        return None

    timestamp = None

    raw_time = obj.get(
        "__REALTIME_TIMESTAMP"
    )

    if raw_time is not None:
        try:
            timestamp = (
                float(raw_time)
                / 1_000_000
            )
        except Exception:
            timestamp = None

    return JournalRecord(
        message=message,
        timestamp=timestamp,
    )
