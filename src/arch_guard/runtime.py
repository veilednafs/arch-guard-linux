from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from arch_guard.dispatcher import (
    DispatchResult,
    EventDispatcher,
)
from arch_guard.policy import apply_policy
from arch_guard.suricata_policy import (
    apply_suricata_policy,
)


@dataclass(slots=True)
class RuntimeStats:
    received: int = 0
    logged: int = 0
    incidents: int = 0
    dispatch_errors: int = 0

    by_sensor: dict[str, int] = field(
        default_factory=dict
    )


class ArchGuardRuntime:
    """
    Arch Guard'ın ortak normalize-event runtime'ı.

    Bu sınıf canlı kaynakları kendisi okumaz.
    Journal/nft/EVE okuyucuları normalize edilmiş
    eventleri buraya teslim eder.

    Akış:

        sensor
          -> normalized event
          -> sensor policy
          -> EventDispatcher
          -> JSONL
          -> optional incident snapshot

    Desktop popup burada gönderilmez.
    """

    def __init__(
        self,
        dispatcher: EventDispatcher,
    ):
        self.dispatcher = dispatcher
        self.stats = RuntimeStats()

    def _record_sensor(
        self,
        sensor: str,
    ) -> None:

        self.stats.received += 1

        self.stats.by_sensor[sensor] = (
            self.stats.by_sensor.get(
                sensor,
                0,
            )
            + 1
        )

    def _dispatch(
        self,
        event: dict[str, Any],
        *,
        sensor: str,
    ) -> DispatchResult:

        event = dict(event)

        event.setdefault(
            "sensor",
            sensor,
        )

        self._record_sensor(
            sensor
        )

        result = self.dispatcher.dispatch(
            event
        )

        if result.logged:
            self.stats.logged += 1

        if result.incident_created:
            self.stats.incidents += 1

        if result.errors:
            self.stats.dispatch_errors += len(
                result.errors
            )

        return result

    def emit_ssh(
        self,
        event: dict[str, Any],
    ) -> DispatchResult:

        normalized = apply_policy(
            dict(event)
        )

        return self._dispatch(
            normalized,
            sensor="ssh",
        )

    def emit_network(
        self,
        event: dict[str, Any],
    ) -> DispatchResult:

        normalized = apply_policy(
            dict(event)
        )

        return self._dispatch(
            normalized,
            sensor="network",
        )

    def emit_suricata(
        self,
        event: dict[str, Any],
    ) -> DispatchResult:

        normalized = (
            apply_suricata_policy(
                dict(event)
            )
        )

        return self._dispatch(
            normalized,
            sensor="suricata",
        )

    def emit_prepared(
        self,
        event: dict[str, Any],
        *,
        sensor: str,
    ) -> DispatchResult:
        """
        Policy/correlation aşamalarından geçmiş eventi
        yeniden policy uygulamadan dispatcher'a verir.
        """

        key = sensor.strip().lower()

        if key in {
            "nft",
            "nftables",
        }:
            key = "network"

        if key not in {
            "ssh",
            "network",
            "suricata",
            "tailscale_scan",
        }:
            raise ValueError(
                f"Unsupported sensor: {sensor!r}"
            )

        return self._dispatch(
            dict(event),
            sensor=key,
        )

    def emit(
        self,
        event: dict[str, Any],
        *,
        sensor: str,
    ) -> DispatchResult:

        key = sensor.strip().lower()

        if key == "ssh":
            return self.emit_ssh(
                event
            )

        if key in {
            "network",
            "nft",
            "nftables",
        }:
            return self.emit_network(
                event
            )

        if key == "suricata":
            return self.emit_suricata(
                event
            )

        raise ValueError(
            f"Unsupported sensor: {sensor!r}"
        )
