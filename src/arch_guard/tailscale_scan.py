from __future__ import annotations

import json
import re
import shutil
import subprocess
import time

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass


WINDOW_SECONDS = 10
THRESHOLD = 25
COOLDOWN_SECONDS = 60


TCPDUMP_SYN_RE = re.compile(
    r"IP\s+127\.0\.0\.1\.(?P<sport>\d+)"
    r"\s+>\s+"
    r"127\.0\.0\.1\.(?P<dport>\d+):"
    r".*Flags\s+\[S\]"
)


@dataclass(frozen=True, slots=True)
class LoopbackSyn:
    source_port: int
    destination_port: int


def parse_loopback_syn(
    line: str,
) -> LoopbackSyn | None:

    match = TCPDUMP_SYN_RE.search(
        line
    )

    if not match:
        return None

    return LoopbackSyn(
        source_port=int(
            match.group("sport")
        ),
        destination_port=int(
            match.group("dport")
        ),
    )


def tailscale_identity(
    *,
    binary: str | None = None,
    runner: Callable = subprocess.run,
) -> dict:
    """
    Tailscale status içinden yalnız güvenli peer
    metadata'sını kullanır.

    Node ID, User ID, keys veya account bilgisi
    döndürülmez.

    Tek aktif veya tek online peer eşlemesi kesin
    kanıt değildir; attribution_confidence=heuristic.
    """

    executable = (
        binary
        or shutil.which("tailscale")
    )

    if not executable:
        return {
            "device": "unknown",
            "source_ip": "unknown",
            "platform": "unknown",
            "identity_scope": "unresolved",
            "attribution_confidence": "none",
        }

    try:
        proc = runner(
            [
                executable,
                "status",
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )

        data = json.loads(
            proc.stdout
            or "{}"
        )

    except Exception:
        return {
            "device": "unknown",
            "source_ip": "unknown",
            "platform": "unknown",
            "identity_scope": "unresolved",
            "attribution_confidence": "none",
        }

    peers = []

    for peer in (
        data.get("Peer")
        or {}
    ).values():

        if not isinstance(
            peer,
            dict,
        ):
            continue

        if not peer.get("Online"):
            continue

        ips = (
            peer.get("TailscaleIPs")
            or []
        )

        peers.append(
            {
                "device":
                    peer.get("HostName")
                    or peer.get("DNSName")
                    or "unknown",

                "source_ip":
                    ips[0]
                    if ips
                    else "unknown",

                "platform":
                    peer.get("OS")
                    or "unknown",

                "active":
                    bool(
                        peer.get("Active")
                    ),
            }
        )

    active = [
        peer
        for peer in peers
        if peer["active"]
    ]

    if len(active) == 1:
        result = dict(
            active[0]
        )

        result.pop(
            "active",
            None,
        )

        result.update(
            {
                "identity_scope":
                    "unique_active_peer",

                "attribution_confidence":
                    "heuristic",
            }
        )

        return result

    if len(peers) == 1:
        result = dict(
            peers[0]
        )

        result.pop(
            "active",
            None,
        )

        result.update(
            {
                "identity_scope":
                    "unique_online_peer",

                "attribution_confidence":
                    "heuristic",
            }
        )

        return result

    return {
        "device":
            (
                "ambiguous"
                if len(peers) > 1
                else "unknown"
            ),

        "source_ip":
            "unknown",

        "platform":
            "unknown",

        "identity_scope":
            (
                f"{len(peers)}_online_peers"
                if peers
                else "unresolved"
            ),

        "attribution_confidence":
            "none",
    }


class TailscaleScanDetector:

    def __init__(
        self,
        *,
        window: int = WINDOW_SECONDS,
        threshold: int = THRESHOLD,
        cooldown: int = COOLDOWN_SECONDS,
        identity_resolver: Callable = tailscale_identity,
    ):
        self.window = int(
            window
        )

        self.threshold = int(
            threshold
        )

        self.cooldown = int(
            cooldown
        )

        self.identity_resolver = (
            identity_resolver
        )

        self.history: deque[
            tuple[float, int]
        ] = deque()

        self.last_alert = 0.0

    def _purge(
        self,
        now: float,
    ) -> None:

        cutoff = (
            now
            - self.window
        )

        while (
            self.history
            and self.history[0][0]
            < cutoff
        ):
            self.history.popleft()

    def process_line(
        self,
        line: str,
        *,
        now: float | None = None,
    ) -> list[dict]:

        syn = parse_loopback_syn(
            line
        )

        if syn is None:
            return []

        timestamp = (
            time.time()
            if now is None
            else float(now)
        )

        self.history.append(
            (
                timestamp,
                syn.destination_port,
            )
        )

        self._purge(
            timestamp
        )

        ports = sorted(
            {
                port
                for _, port
                in self.history
            }
        )

        if (
            len(ports)
            < self.threshold
        ):
            return []

        if (
            timestamp
            - self.last_alert
            < self.cooldown
        ):
            return []

        identity = (
            self.identity_resolver()
        )

        event = {
            "event":
                "tailscale_port_scan",

            "severity":
                "HIGH",

            "device":
                identity.get(
                    "device",
                    "unknown",
                ),

            "source_ip":
                identity.get(
                    "source_ip",
                    "unknown",
                ),

            "platform":
                identity.get(
                    "platform",
                    "unknown",
                ),

            "identity_scope":
                identity.get(
                    "identity_scope",
                    "unresolved",
                ),

            "attribution_confidence":
                identity.get(
                    "attribution_confidence",
                    "none",
                ),

            "transport":
                "tailscale/userspace-proxy",

            "proxy_source_ip":
                "127.0.0.1",

            "proxy_destination_ip":
                "127.0.0.1",

            "ports":
                ports,

            "unique_ports":
                len(ports),

            "window_seconds":
                self.window,

            "threshold":
                self.threshold,

            "cooldown_seconds":
                self.cooldown,

            "notify":
                False,

            "snapshot":
                False,
        }

        self.last_alert = (
            timestamp
        )

        return [
            event
        ]
