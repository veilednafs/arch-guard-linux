#!/usr/bin/env python3

from __future__ import annotations

import json
import sys

from pathlib import Path

from arch_guard.events import (
    EventWriter,
    iso_from_epoch,
)
from arch_guard.journal import parse_journal_line
from arch_guard.pipeline import SSHPipeline


def goster(event: dict) -> None:
    print()
    print(
        "OLAY       :",
        event.get("event", "-"),
    )

    print(
        "SEVİYE     :",
        event.get("severity", "-"),
    )

    print(
        "KULLANICI  :",
        event.get("user", "-"),
    )

    print(
        "SSH KAYNAK :",
        event.get("ssh_source_ip", "-"),
    )

    print(
        "GERÇEK IP  :",
        event.get("real_source_ip", "-"),
    )

    print(
        "TAŞIMA     :",
        event.get("transport", "-"),
    )

    print(
        "CİHAZ      :",
        event.get("device", "-"),
    )

    print(
        "PLATFORM   :",
        event.get("platform", "-"),
    )

    print(
        "KİMLİK     :",
        event.get("identity_scope", "-"),
    )

    print(
        "GÜVEN      :",
        event.get(
            "attribution_confidence",
            "-",
        ),
    )

    print(
        "BİLDİRİM   :",
        event.get("notify", False),
    )

    print(
        "ZAMAN      :",
        event.get("timestamp", "-"),
    )

    print("-" * 40)

    sys.stdout.flush()


def main() -> int:
    output = Path(
        "var/live-events.jsonl"
    )

    writer = EventWriter(output)
    pipeline = SSHPipeline()

    journal_count = 0
    recognized_count = 0
    event_count = 0
    notify_count = 0

    print()
    print("CANLI İZLEME BAŞLADI")
    print(
        "Şimdi bir SSH bağlantısı yapıp çıkabilirsin."
    )
    print()

    sys.stdout.flush()

    for line in sys.stdin:
        record = parse_journal_line(
            line.strip()
        )

        if record is None:
            continue

        journal_count += 1

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

        recognized_count += 1

        for event in events:
            writer.write(event)

            event_count += 1

            if event.get("notify"):
                notify_count += 1

            goster(event)

    print()
    print("========================================")
    print(" CANLI PROVA SONUCU")
    print("========================================")

    print(
        "Journal kaydı    :",
        journal_count,
    )

    print(
        "Tanınan SSH      :",
        recognized_count,
    )

    print(
        "Yazılan event    :",
        event_count,
    )

    print(
        "Bildirim adayı   :",
        notify_count,
    )

    print(
        "Development log  :",
        output,
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print("Canlı SSH izleme kullanıcı tarafından durduruldu.")
        raise SystemExit(0)
