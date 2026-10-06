#!/usr/bin/env python3

from __future__ import annotations

import json
import sys

from collections import Counter
from pathlib import Path

from arch_guard.events import (
    EventWriter,
    iso_from_epoch,
)
from arch_guard.journal import (
    parse_journal_line,
)
from arch_guard.network_pipeline import (
    NetworkPipeline,
)


def identity_off(
    event: dict,
) -> dict:
    # Geçmiş olaya bugünkü neighbor tablosunu
    # yapıştırmıyoruz.
    return dict(event)


def listener_off(
    event: dict,
) -> dict:
    # Geçmiş olaya bugünkü listener durumunu
    # yapıştırmıyoruz.
    return dict(event)


def main() -> int:
    output = Path(
        "var/dev-network-events.jsonl"
    )

    writer = EventWriter(
        output
    )

    pipeline = NetworkPipeline(
        identity_resolver=identity_off,
        listener_resolver=listener_off,
    )

    stats = {
        "journal": 0,
        "recognized": 0,
        "events": 0,
        "notification_candidates": 0,
    }

    counts = Counter()

    for line in sys.stdin:
        record = parse_journal_line(
            line.strip()
        )

        if record is None:
            continue

        stats["journal"] += 1

        timestamp = (
            iso_from_epoch(
                record.timestamp
            )
            if record.timestamp is not None
            else None
        )

        events = pipeline.process_message(
            record.message,
            now=record.timestamp,
            event_timestamp=timestamp,
        )

        if not events:
            continue

        stats["recognized"] += 1

        for event in events:
            writer.write(
                event
            )

            stats["events"] += 1

            counts[
                event["event"]
            ] += 1

            if event.get(
                "notify"
            ):
                stats[
                    "notification_candidates"
                ] += 1

    print()
    print("========================================")
    print(" NETWORK REPLAY SONUCU")
    print("========================================")

    print(
        "Okunan kernel kaydı :",
        stats["journal"],
    )

    print(
        "Tanınan nft kaydı   :",
        stats["recognized"],
    )

    print(
        "Yazılan event       :",
        stats["events"],
    )

    print(
        "Bildirim adayı      :",
        stats["notification_candidates"],
    )

    print()
    print("Olay türleri:")

    if counts:
        for name, count in sorted(
            counts.items()
        ):
            print(
                f"  {name:<28} {count}"
            )
    else:
        print(
            "  Tanınan AGNET kaydı bulunmadı."
        )

    print()
    print(
        "Geliştirme logu     :",
        output,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
