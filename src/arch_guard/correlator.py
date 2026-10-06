from __future__ import annotations

import time

from collections import defaultdict, deque
from dataclasses import dataclass

from arch_guard.config import SSHConfig
from arch_guard.events import make_event


@dataclass(slots=True)
class FailureRecord:
    timestamp: float
    user: str | None
    event_type: str


class SSHCorrelator:
    """
    SSH olaylarını zaman penceresi içinde ilişkilendirir.

    Sensör yalnızca gözlem üretir.
    Brute-force kararı burada verilir.
    """

    FAILURE_EVENTS = {
        "ssh_auth_failure",
        "ssh_invalid_user",
    }

    def __init__(
        self,
        *,
        window: int = 60,
        high_threshold: int = 3,
        critical_threshold: int = 5,
    ):
        if window <= 0:
            raise ValueError(
                "window sıfırdan büyük olmalı"
            )

        if high_threshold <= 0:
            raise ValueError(
                "high_threshold sıfırdan büyük olmalı"
            )

        if critical_threshold < high_threshold:
            raise ValueError(
                "critical_threshold, high_threshold'dan "
                "küçük olamaz"
            )

        self.window = int(window)
        self.high_threshold = int(high_threshold)
        self.critical_threshold = int(
            critical_threshold
        )

        self._failures: dict[
            str,
            deque[FailureRecord],
        ] = defaultdict(deque)

        # 0 = alarm yok
        # 1 = HIGH üretildi
        # 2 = CRITICAL üretildi
        self._level: dict[str, int] = {}

    @classmethod
    def from_config(
        cls,
        config: SSHConfig,
    ) -> "SSHCorrelator":
        return cls(
            window=config.brute_force_window,
            high_threshold=config.high_threshold,
            critical_threshold=config.critical_threshold,
        )

    def _purge(
        self,
        source_ip: str,
        now: float,
    ) -> None:
        queue = self._failures[source_ip]

        while queue:
            age = now - queue[0].timestamp

            if age <= self.window:
                break

            queue.popleft()

        count = len(queue)
        current_level = self._level.get(
            source_ip,
            0,
        )

        if count < self.high_threshold:
            self._level[source_ip] = 0

        elif (
            count < self.critical_threshold
            and current_level > 1
        ):
            self._level[source_ip] = 1

        if not queue:
            self._failures.pop(
                source_ip,
                None,
            )

            self._level.pop(
                source_ip,
                None,
            )

    def _attempted_users(
        self,
        source_ip: str,
    ) -> list[str]:
        users = {
            item.user
            for item in self._failures.get(
                source_ip,
                (),
            )
            if item.user
        }

        return sorted(users)

    def process(
        self,
        event: dict,
        *,
        now: float | None = None,
    ) -> list[dict]:

        now = (
            time.monotonic()
            if now is None
            else float(now)
        )

        event_type = event.get("event")

        if event_type in self.FAILURE_EVENTS:
            return self._process_failure(
                event,
                now,
            )

        if event_type == "ssh_auth_success":
            return self._process_success(
                event,
                now,
            )

        return []

    def _process_failure(
        self,
        event: dict,
        now: float,
    ) -> list[dict]:

        source_ip = event.get(
            "ssh_source_ip"
        )

        if not source_ip:
            return []

        source_ip = str(source_ip)

        self._purge(
            source_ip,
            now,
        )

        queue = self._failures[
            source_ip
        ]

        queue.append(
            FailureRecord(
                timestamp=now,
                user=event.get("user"),
                event_type=str(
                    event.get("event")
                ),
            )
        )

        count = len(queue)
        previous_level = self._level.get(
            source_ip,
            0,
        )

        severity = None
        new_level = previous_level

        if (
            count >= self.critical_threshold
            and previous_level < 2
        ):
            severity = "CRITICAL"
            new_level = 2

        elif (
            count >= self.high_threshold
            and previous_level < 1
        ):
            severity = "HIGH"
            new_level = 1

        self._level[source_ip] = new_level

        if severity is None:
            return []

        derived = make_event(
            "ssh_bruteforce",
            severity,
            sensor="correlator",
            notify=False,
            timestamp=event.get("timestamp"),
            source_ip=source_ip,
            failure_count=count,
            window_seconds=self.window,
            attempted_users=self._attempted_users(
                source_ip
            ),
            correlation="ssh_failure_window",
        )

        return [derived]

    def _process_success(
        self,
        event: dict,
        now: float,
    ) -> list[dict]:

        source_ip = event.get(
            "ssh_source_ip"
        )

        if not source_ip:
            return []

        source_ip = str(source_ip)

        self._purge(
            source_ip,
            now,
        )

        queue = self._failures.get(
            source_ip
        )

        if not queue:
            return []

        count = len(queue)

        if count >= self.critical_threshold:
            severity = "CRITICAL"

        elif count >= self.high_threshold:
            severity = "HIGH"

        else:
            severity = "WARNING"

        users = self._attempted_users(
            source_ip
        )

        derived = make_event(
            "ssh_success_after_failures",
            severity,
            sensor="correlator",
            notify=False,
            timestamp=event.get("timestamp"),
            source_ip=source_ip,
            user=event.get("user"),
            failure_count=count,
            attempted_users=users,
            window_seconds=self.window,
            correlation=(
                "successful_auth_after_failures"
            ),
        )

        # Başarılı oturumdan sonra aynı başarısızlıkları
        # tekrar tekrar korele etmiyoruz.
        self._failures.pop(
            source_ip,
            None,
        )

        self._level.pop(
            source_ip,
            None,
        )

        return [derived]
