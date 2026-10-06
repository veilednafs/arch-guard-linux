#!/usr/bin/env python3

from pathlib import Path
import sys

from arch_guard.events import EventWriter
from arch_guard.pipeline import SSHPipeline
from arch_guard.stream import process_journal_stream


def identity_off(event: dict) -> dict:
    # Geçmiş journal kaydını bugünkü socket
    # durumuyla yanlış eşleştirmemek için replay
    # sırasında canlı kimlik çözümleme kapalıdır.
    return dict(event)


def main() -> int:
    output = Path(
        "var/dev-events.jsonl"
    )

    pipeline = SSHPipeline(
        identity_resolver=identity_off
    )

    writer = EventWriter(output)

    stats = process_journal_stream(
        sys.stdin,
        pipeline=pipeline,
        writer=writer,
    )

    print()
    print("========================================")
    print(" GELİŞTİRME REPLAY SONUCU")
    print("========================================")

    print(
        "Okunan journal       :",
        stats["journal"],
    )

    print(
        "Tanınan SSH kaydı    :",
        stats["recognized"],
    )

    print(
        "Yazılan event        :",
        stats["events"],
    )

    print(
        "Bildirim adayı       :",
        stats["notification_candidates"],
    )

    print(
        "Geliştirme logu      :",
        output,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
