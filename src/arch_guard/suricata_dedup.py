from __future__ import annotations

import time


class SuricataDeduplicator:

    def __init__(
        self,
        seconds: int = 30,
    ):
        if seconds < 0:
            raise ValueError(
                "Dedup süresi negatif olamaz"
            )

        self.seconds = int(
            seconds
        )

        self._seen: dict[
            tuple,
            float,
        ] = {}

    @staticmethod
    def key(
        event: dict,
    ) -> tuple:

        return (
            event.get(
                "sensor_profile",
                "default",
            ),
            event.get(
                "signature_id"
            ),
            event.get(
                "flow_id"
            ),
            event.get(
                "protocol"
            ),
            event.get(
                "source_ip"
            ),
            event.get(
                "source_port"
            ),
            event.get(
                "destination_ip"
            ),
            event.get(
                "destination_port"
            ),
        )

    def accept(
        self,
        event: dict,
        *,
        now: float | None = None,
    ) -> bool:

        current = (
            time.monotonic()
            if now is None
            else float(now)
        )

        key = self.key(
            event
        )

        previous = self._seen.get(
            key
        )

        if (
            previous is not None
            and current - previous
            < self.seconds
        ):
            return False

        self._seen[
            key
        ] = current

        return True
