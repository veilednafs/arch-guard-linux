from __future__ import annotations

import json

from datetime import datetime
from pathlib import Path
from typing import Any


VALID_SEVERITIES = {
    "INFO",
    "WARNING",
    "HIGH",
    "CRITICAL",
}


def now_iso() -> str:
    return (
        datetime.now()
        .astimezone()
        .isoformat(timespec="seconds")
    )


def iso_from_epoch(value: float) -> str:
    return (
        datetime.fromtimestamp(float(value))
        .astimezone()
        .isoformat(timespec="seconds")
    )


def normalize_severity(value: str) -> str:
    value = str(value).upper()

    if value not in VALID_SEVERITIES:
        return "WARNING"

    return value


def make_event(
    event_type: str,
    severity: str,
    *,
    sensor: str | None = None,
    title: str | None = None,
    body: str | None = None,
    notify: bool = False,
    direction: str | None = None,
    timestamp: str | None = None,
    **extra: Any,
) -> dict[str, Any]:

    event = {
        "timestamp": timestamp or now_iso(),
        "event": str(event_type),
        "severity": normalize_severity(severity),
        "notify": bool(notify),
    }

    optional = {
        "sensor": sensor,
        "title": title,
        "body": body,
        "direction": direction,
    }

    for key, value in optional.items():
        if value is not None:
            event[key] = value

    for key, value in extra.items():
        if value is not None:
            event[key] = value

    return event


class EventWriter:
    def __init__(self, path: Path):
        self.path = Path(path)

    def write(self, event: dict[str, Any]) -> None:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.path.open(
            "a",
            encoding="utf-8",
        ) as f:
            f.write(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
