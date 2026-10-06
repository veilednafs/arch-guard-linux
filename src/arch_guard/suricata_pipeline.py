from __future__ import annotations

from collections.abc import Callable

from arch_guard.sensors.suricata import (
    parse_eve_line,
)
from arch_guard.suricata_dedup import (
    SuricataDeduplicator,
)
from arch_guard.suricata_direction_runtime import (
    enrich_suricata_direction,
)
from arch_guard.suricata_policy import (
    apply_suricata_policy,
)


Resolver = Callable[
    [dict],
    dict,
]


class SuricataPipeline:
    """
    Suricata işlem zinciri:

    EVE JSON
      -> parser
      -> direction
      -> dedup
      -> policy
    """

    def __init__(
        self,
        *,
        profile: str = "default",
        dedup_seconds: int = 30,
        direction_resolver: Resolver | None = None,
        deduplicator: SuricataDeduplicator | None = None,
    ):
        self.profile = str(profile)

        self.direction_resolver = (
            direction_resolver
            if direction_resolver is not None
            else enrich_suricata_direction
        )

        self.deduplicator = (
            deduplicator
            if deduplicator is not None
            else SuricataDeduplicator(
                seconds=dedup_seconds
            )
        )

        self.lines_seen = 0
        self.alerts_seen = 0
        self.duplicates_dropped = 0
        self.events_emitted = 0

    def process_line(
        self,
        line: str,
        *,
        now: float | None = None,
    ) -> list[dict]:

        self.lines_seen += 1

        event = parse_eve_line(
            line,
            sensor_profile=self.profile,
        )

        if event is None:
            return []

        self.alerts_seen += 1

        event = self.direction_resolver(
            event
        )

        if not self.deduplicator.accept(
            event,
            now=now,
        ):
            self.duplicates_dropped += 1
            return []

        event = apply_suricata_policy(
            event
        )

        self.events_emitted += 1

        return [event]
