#!/usr/bin/env python3

from __future__ import annotations

import sys

from collections import Counter

from arch_guard.journal import parse_journal_line
from arch_guard.pipeline import SSHPipeline


def safe(value):
    if value is None:
        return "-"

    return str(value)


def main() -> int:
    pipeline = SSHPipeline()

    total_records = 0
    recognized_records = 0
    produced_events = []
    counts = Counter()

    for line in sys.stdin:
        line = line.strip()

        if not line:
            continue

        record = parse_journal_line(line)

        if record is None:
            continue

        total_records += 1

        events = pipeline.process_message(
            record.message,
            now=record.timestamp,
        )

        if not events:
            continue

        recognized_records += 1

        for event in events:
            counts[event["event"]] += 1
            produced_events.append(event)

    print()
    print("========================================")
    print(" SSH JOURNAL PROVA SONUCU")
    print("========================================")

    print(
        "Okunan journal kaydı :",
        total_records,
    )

    print(
        "Tanınan SSH kaydı    :",
        recognized_records,
    )

    print(
        "Üretilen olay        :",
        len(produced_events),
    )

    notifications = sum(
        1
        for event in produced_events
        if event.get("notify")
    )

    print(
        "Bildirim adayı       :",
        notifications,
    )

    print()
    print("Olay türleri:")

    if counts:
        for name, count in sorted(
            counts.items()
        ):
            print(
                f"  {name:<30} {count}"
            )
    else:
        print(
            "  Tanınan SSH olayı bulunmadı."
        )

    print()
    print("Son tanınan olaylar:")

    for event in produced_events[-10:]:
        print(
            "  "
            f"{safe(event.get('severity')):<8} "
            f"{safe(event.get('event')):<28} "
            f"kullanıcı={safe(event.get('user'))} "
            f"kaynak={safe(event.get('ssh_source_ip') or event.get('source_ip'))} "
            f"bildirim={safe(event.get('notify'))}"
        )

    print()
    print(
        "NOT: Bu prova hiçbir bildirim göndermedi."
    )

    print(
        "NOT: events.jsonl dosyasına yazılmadı."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
