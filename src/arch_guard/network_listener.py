from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ListenerInfo:
    listening: bool
    listener_scope: str
    listener: str | None = None


def classify_listener_output(
    raw: str,
    port: int,
) -> ListenerInfo:

    raw = raw.strip()

    if not raw:
        return ListenerInfo(
            listening=False,
            listener_scope="NO_LISTENER",
            listener=None,
        )

    joined = " | ".join(
        line.strip()
        for line in raw.splitlines()
        if line.strip()
    )

    loopback_patterns = (
        f"127.0.0.1:{port}",
        f"127.0.2.2:{port}",
        f"127.0.2.3:{port}",
        f"[::1]:{port}",
    )

    all_patterns = (
        f"0.0.0.0:{port}",
        f"*:{port}",
        f"[::]:{port}",
    )

    if any(
        pattern in joined
        for pattern in loopback_patterns
    ):
        scope = "LOOPBACK_ONLY"

    elif any(
        pattern in joined
        for pattern in all_patterns
    ):
        scope = "ALL_INTERFACES"

    else:
        scope = "BOUND_INTERFACE"

    return ListenerInfo(
        listening=True,
        listener_scope=scope,
        listener=joined,
    )
