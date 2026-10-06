#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
import time

from pathlib import Path

from arch_guard.events import EventWriter
from arch_guard.suricata_pipeline import (
    SuricataPipeline,
)


def show(event: dict) -> None:
    print()
    print(
        "OLAY        :",
        event.get("event", "-"),
    )

    print(
        "PROFİL      :",
        event.get("sensor_profile", "-"),
    )

    print(
        "SEVİYE      :",
        event.get("severity", "-"),
    )

    print(
        "YÖN         :",
        event.get("direction", "-"),
    )

    print(
        "KANIT       :",
        event.get(
            "direction_evidence",
            "-",
        ),
    )

    print(
        "SID         :",
        event.get("signature_id", "-"),
    )

    print(
        "SIGNATURE   :",
        event.get("signature", "-"),
    )

    print(
        "KAYNAK      :",
        (
            f"{event.get('source_ip', '-')}:"
            f"{event.get('source_port', '-')}"
        ),
    )

    print(
        "HEDEF       :",
        (
            f"{event.get('destination_ip', '-')}:"
            f"{event.get('destination_port', '-')}"
        ),
    )

    print(
        "SUPPRESSED  :",
        event.get("suppressed", False),
    )

    print(
        "SEBEP       :",
        event.get(
            "suppression_reason"
        ) or "-",
    )

    print(
        "BİLDİRİM    :",
        event.get("notify", False),
    )

    print(
        "SNAPSHOT    :",
        event.get("snapshot", False),
    )

    print(
        "ZAMAN       :",
        event.get("timestamp", "-"),
    )

    print("-" * 52)

    sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--profile",
        default="default",
    )

    parser.add_argument(
        "--output",
        default=(
            "var/live-suricata-events.jsonl"
        ),
    )

    args = parser.parse_args()

    pipeline = SuricataPipeline(
        profile=args.profile
    )

    writer = EventWriter(
        Path(args.output)
    )

    suppressed = 0
    notify = 0
    snapshots = 0

    print()
    print("CANLI SURICATA İZLEME BAŞLADI")
    print(
        "Profil:",
        args.profile,
    )
    print()
    sys.stdout.flush()

    try:
        for line in sys.stdin:
            events = pipeline.process_line(
                line,
                now=time.monotonic(),
            )

            for event in events:
                writer.write(
                    event
                )

                if event.get(
                    "suppressed"
                ):
                    suppressed += 1

                if event.get(
                    "notify"
                ):
                    notify += 1

                if event.get(
                    "snapshot"
                ):
                    snapshots += 1

                show(
                    event
                )

    except KeyboardInterrupt:
        print()
        print(
            "Canlı Suricata izleme "
            "kullanıcı tarafından durduruldu."
        )

    print()
    print("========================================")
    print(" CANLI SURICATA ÖZETİ")
    print("========================================")

    print(
        "Okunan EVE satırı :",
        pipeline.lines_seen,
    )

    print(
        "Alert görüldü     :",
        pipeline.alerts_seen,
    )

    print(
        "Dedup düşürdü     :",
        pipeline.duplicates_dropped,
    )

    print(
        "Yazılan event     :",
        pipeline.events_emitted,
    )

    print(
        "Suppressed        :",
        suppressed,
    )

    print(
        "Bildirim adayı    :",
        notify,
    )

    print(
        "Snapshot adayı    :",
        snapshots,
    )

    print(
        "Development log   :",
        args.output,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
