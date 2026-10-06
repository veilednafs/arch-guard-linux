from __future__ import annotations

from typing import Iterable

from arch_guard.events import EventWriter, iso_from_epoch
from arch_guard.journal import parse_journal_line
from arch_guard.pipeline import SSHPipeline


def process_journal_stream(
    lines: Iterable[str],
    *,
    pipeline: SSHPipeline,
    writer: EventWriter,
) -> dict[str, int]:

    stats = {
        "journal": 0,
        "recognized": 0,
        "events": 0,
        "notification_candidates": 0,
    }

    for line in lines:
        record = parse_journal_line(
            line.strip()
        )

        if record is None:
            continue

        stats["journal"] += 1

        event_timestamp = (
            iso_from_epoch(record.timestamp)
            if record.timestamp is not None
            else None
        )

        events = pipeline.process_message(
            record.message,
            now=record.timestamp,
            event_timestamp=event_timestamp,
        )

        if not events:
            continue

        stats["recognized"] += 1

        for event in events:
            writer.write(event)

            stats["events"] += 1

            if event.get("notify"):
                stats[
                    "notification_candidates"
                ] += 1

    return stats
