#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path

from arch_guard.events import (
    EventWriter,
    iso_from_epoch,
)
from arch_guard.journal import parse_journal_line
from arch_guard.network_pipeline import NetworkPipeline


def show(event: dict) -> None:
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
        "KAYNAK IP  :",
        event.get("source_ip", "-"),
    )

    print(
        "KAYNAK MAC :",
        event.get("source_mac") or "N/A",
    )

    print(
        "KAPSAM     :",
        event.get("source_scope", "-"),
    )

    print(
        "HEDEF      :",
        (
            f"{event.get('destination_ip', '-')}:"
            f"{event.get('destination_port', '-')}"
        ),
    )

    print(
        "ARAYÜZ     :",
        event.get("interface", "-"),
    )

    print(
        "TAŞIMA     :",
        event.get("transport", "-"),
    )

    print(
        "LISTENER   :",
        event.get("listener_scope", "-"),
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

    if event.get("event") == "network_port_scan":
        print(
            "PORTLAR    :",
            event.get("ports", []),
        )

    print("-" * 40)
    sys.stdout.flush()


def main() -> int:
    output = Path(
        "var/live-network-events.jsonl"
    )

    writer = EventWriter(output)
    pipeline = NetworkPipeline()

    journal_count = 0
    recognized_count = 0
    event_count = 0

    print()
    print("CANLI AĞ İZLEME BAŞLADI")
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
            iso_from_epoch(record.timestamp)
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
            show(event)

    print()
    print("========================================")
    print(" CANLI NETWORK PROVA SONUCU")
    print("========================================")
    print("Kernel kaydı     :", journal_count)
    print("Tanınan nft      :", recognized_count)
    print("Yazılan event    :", event_count)
    print("Development log  :", output)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print("Canlı ağ izleme kullanıcı tarafından durduruldu.")
        raise SystemExit(0)
