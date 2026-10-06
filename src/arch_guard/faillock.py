from __future__ import annotations

import re
import shutil
import subprocess
import time

from collections.abc import Callable


Counter = Callable[[str], int]
Sleeper = Callable[[float], None]


def faillock_count(
    user: str,
    *,
    binary: str | None = None,
    runner: Callable = subprocess.run,
) -> int:
    """
    PAM faillock içindeki geçerli kayıt sayısını döndürür.

    Hata durumunda -1 döner; bu durumda güvenlik olayı
    uydurulmaz.
    """

    if not user:
        return -1

    executable = (
        binary
        or shutil.which("faillock")
        or "/usr/bin/faillock"
    )

    try:
        proc = runner(
            [
                executable,
                "--user",
                user,
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return -1

    count = 0

    for line in (
        proc.stdout
        or ""
    ).splitlines():

        if re.search(
            r"\sV\s*$",
            line,
        ):
            count += 1

    return count


class FaillockDetector:
    """
    SSH auth failure sonrasında PAM faillock durumunu
    kontrol eder.

    Bir kullanıcı threshold seviyesine ulaştığında yalnız
    bir ssh_account_locked eventi üretir.

    Başarılı SSH auth geldiğinde alarm latch'i sıfırlanır.
    """

    def __init__(
        self,
        *,
        threshold: int = 3,
        delay_seconds: float = 0.15,
        counter: Counter = faillock_count,
        sleeper: Sleeper = time.sleep,
    ):
        self.threshold = int(
            threshold
        )

        self.delay_seconds = float(
            delay_seconds
        )

        self.counter = counter
        self.sleeper = sleeper

        self.alerted_users: set[str] = set()

    def process(
        self,
        event: dict,
    ) -> list[dict]:

        event_type = str(
            event.get("event")
            or ""
        )

        user = str(
            event.get("user")
            or ""
        )

        if not user:
            return []

        if event_type == "ssh_auth_success":
            self.alerted_users.discard(
                user
            )

            return []

        if event_type != "ssh_auth_failure":
            return []

        if self.delay_seconds > 0:
            self.sleeper(
                self.delay_seconds
            )

        count = self.counter(
            user
        )

        if count < 0:
            return []

        if count < self.threshold:
            self.alerted_users.discard(
                user
            )

            return []

        if user in self.alerted_users:
            return []

        self.alerted_users.add(
            user
        )

        locked = dict(
            event
        )

        locked.update(
            {
                "event":
                    "ssh_account_locked",

                "severity":
                    "CRITICAL",

                "pam_failure_count":
                    count,

                "correlation":
                    "pam_faillock",

                # Asıl policy birazdan uygular.
                "notify":
                    False,

                "snapshot":
                    False,
            }
        )

        return [
            locked
        ]
