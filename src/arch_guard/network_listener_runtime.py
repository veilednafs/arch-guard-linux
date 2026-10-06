from __future__ import annotations

import shutil
import subprocess

from arch_guard.network_listener import (
    ListenerInfo,
    classify_listener_output,
)


def lookup_listener(
    port: int,
) -> ListenerInfo:

    ss_bin = shutil.which("ss")

    if not ss_bin:
        return ListenerInfo(
            listening=False,
            listener_scope="UNKNOWN",
            listener=None,
        )

    try:
        proc = subprocess.run(
            [
                ss_bin,
                "-H",
                "-lntp",
                f"sport = :{int(port)}",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return ListenerInfo(
            listening=False,
            listener_scope="UNKNOWN",
            listener=None,
        )

    return classify_listener_output(
        proc.stdout,
        int(port),
    )


def enrich_listener(
    event: dict,
) -> dict:

    result = dict(event)

    port = result.get(
        "destination_port"
    )

    if port is None:
        return result

    try:
        port = int(port)
    except (
        TypeError,
        ValueError,
    ):
        return result

    info = lookup_listener(
        port
    )

    result.update(
        {
            "listening":
                info.listening,

            "listener_scope":
                info.listener_scope,

            "listener":
                info.listener,
        }
    )

    return result
