from __future__ import annotations

import time

from collections import defaultdict, deque
from dataclasses import dataclass

from arch_guard.config import NetworkConfig
from arch_guard.events import make_event


@dataclass(slots=True)
class ProbeRecord:
    timestamp: float
    destination_port: int


class NetworkScanCorrelator:
    """
    Aynı kaynak IP'nin kısa zaman penceresinde
    kaç farklı hedef TCP portuna dokunduğunu izler.

    Legacy davranış:
      - pencere: 10 saniye
      - eşik: 6 farklı port
      - cooldown: 60 saniye
    """

    def __init__(
        self,
        *,
        window: int = 10,
        threshold: int = 6,
        cooldown: int = 60,
    ):
        if window <= 0:
            raise ValueError(
                "window sıfırdan büyük olmalı"
            )

        if threshold <= 0:
            raise ValueError(
                "threshold sıfırdan büyük olmalı"
            )

        if cooldown < 0:
            raise ValueError(
                "cooldown negatif olamaz"
            )

        self.window = int(window)
        self.threshold = int(threshold)
        self.cooldown = int(cooldown)

        self._history: dict[
            str,
            deque[ProbeRecord],
        ] = defaultdict(deque)

        self._last_alert: dict[
            str,
            float,
        ] = {}

    @classmethod
    def from_config(
        cls,
        config: NetworkConfig,
    ) -> "NetworkScanCorrelator":

        return cls(
            window=config.port_scan_window,
            threshold=config.port_scan_threshold,
            cooldown=config.cooldown,
        )

    def _purge(
        self,
        source_ip: str,
        now: float,
    ) -> None:

        history = self._history[source_ip]

        while history:
            age = (
                now
                - history[0].timestamp
            )

            if age <= self.window:
                break

            history.popleft()

        if not history:
            self._history.pop(
                source_ip,
                None,
            )

    def process(
        self,
        event: dict,
        *,
        now: float | None = None,
    ) -> list[dict]:

        if event.get("event") != "network_probe":
            return []

        source_ip = event.get(
            "source_ip"
        )

        destination_port = event.get(
            "destination_port"
        )

        if (
            source_ip is None
            or destination_port is None
        ):
            return []

        source_ip = str(source_ip)

        try:
            destination_port = int(
                destination_port
            )
        except (
            TypeError,
            ValueError,
        ):
            return []

        current = (
            time.monotonic()
            if now is None
            else float(now)
        )

        self._purge(
            source_ip,
            current,
        )

        history = self._history[
            source_ip
        ]

        history.append(
            ProbeRecord(
                timestamp=current,
                destination_port=destination_port,
            )
        )

        ports = sorted(
            {
                item.destination_port
                for item in history
            }
        )

        if len(ports) < self.threshold:
            return []

        previous = self._last_alert.get(
            source_ip
        )

        if (
            previous is not None
            and current - previous
            < self.cooldown
        ):
            return []

        self._last_alert[
            source_ip
        ] = current

        derived = make_event(
            "network_port_scan",
            "CRITICAL",
            sensor="correlator",
            notify=False,
            timestamp=event.get(
                "timestamp"
            ),

            source_ip=source_ip,

            source_mac=event.get(
                "source_mac"
            ),

            source_scope=event.get(
                "source_scope"
            ),

            attribution_confidence=event.get(
                "attribution_confidence"
            ),

            route_interface=event.get(
                "route_interface"
            ),

            gateway=event.get(
                "gateway"
            ),

            destination_ip=event.get(
                "destination_ip"
            ),

            interface=event.get(
                "interface"
            ),

            transport=event.get(
                "transport"
            ),

            capture_profile=event.get(
                "capture_profile"
            ),

            ports=ports,
            unique_ports=len(ports),
            window_seconds=self.window,
            cooldown_seconds=self.cooldown,

            correlation=(
                "unique_destination_ports"
            ),
        )

        return [derived]
