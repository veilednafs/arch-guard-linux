from __future__ import annotations

import json
import time

from pathlib import Path

from arch_guard.notifier import (
    NotifySendBackend,
    notify_event,
)


class NotificationConsumer:

    def __init__(
        self,
        *,
        backend=None,
    ):
        self.backend = (
            backend
            if backend is not None
            else NotifySendBackend()
        )

        self.lines_seen = 0
        self.events_seen = 0
        self.notifications_sent = 0

    def process_line(
        self,
        line: str,
    ) -> bool:

        self.lines_seen += 1

        try:
            event = json.loads(
                line
            )
        except Exception:
            return False

        if not isinstance(
            event,
            dict,
        ):
            return False

        self.events_seen += 1

        if event.get("notify") is not True:
            return False

        sent = notify_event(
            event,
            self.backend,
        )

        if sent:
            self.notifications_sent += 1

        return sent


def follow_event_log(
    path: Path,
    *,
    consumer: NotificationConsumer,
    from_start: bool = False,
    poll_seconds: float = 0.25,
) -> None:

    path = Path(path)

    handle = None
    inode = None

    try:
        while True:

            if handle is None:
                if not path.exists():
                    time.sleep(
                        poll_seconds
                    )
                    continue

                handle = path.open(
                    "r",
                    encoding="utf-8",
                    errors="replace",
                )

                inode = (
                    path.stat()
                    .st_ino
                )

                if not from_start:
                    handle.seek(
                        0,
                        2,
                    )

            line = handle.readline()

            if line:
                consumer.process_line(
                    line
                )
                continue

            time.sleep(
                poll_seconds
            )

            try:
                stat = path.stat()
            except FileNotFoundError:
                handle.close()
                handle = None
                inode = None
                continue

            if (
                stat.st_ino != inode
                or stat.st_size
                < handle.tell()
            ):
                handle.close()
                handle = None
                inode = None

    except KeyboardInterrupt:
        return

    finally:
        if handle is not None:
            handle.close()


def run_notifier(
    event_log: Path,
    *,
    from_start: bool = False,
) -> int:

    consumer = NotificationConsumer()

    if not consumer.backend.available:
        raise RuntimeError(
            "notify-send bulunamadı."
        )

    follow_event_log(
        Path(event_log),
        consumer=consumer,
        from_start=from_start,
    )

    return 0
