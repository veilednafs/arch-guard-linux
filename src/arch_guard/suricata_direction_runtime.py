from __future__ import annotations

import json
import shutil
import subprocess

from arch_guard.suricata_direction import (
    classify_direction,
    conntrack_original_match_text,
    socket_flow_match_text,
)


def _run(
    args: list[str],
    *,
    timeout: float = 3,
) -> str:

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception:
        return ""

    if proc.returncode != 0:
        return ""

    return proc.stdout


def local_ips() -> set[str]:

    ip_bin = shutil.which(
        "ip"
    )

    if not ip_bin:
        return set()

    raw = _run(
        [
            ip_bin,
            "-j",
            "addr",
            "show",
            "up",
        ]
    )

    try:
        data = json.loads(
            raw or "[]"
        )
    except Exception:
        return set()

    result: set[str] = set()

    for interface in data:
        if interface.get(
            "ifname"
        ) == "lo":
            continue

        for address in interface.get(
            "addr_info",
            [],
        ):
            value = address.get(
                "local"
            )

            if value:
                result.add(
                    str(value)
                )

    return result


def conntrack_return_match(
    event: dict,
) -> bool:

    conntrack = shutil.which(
        "conntrack"
    )

    if not conntrack:
        return False

    proto = str(
        event.get("protocol") or ""
    ).lower()

    if proto not in {
        "tcp",
        "udp",
    }:
        return False

    raw = _run(
        [
            conntrack,
            "-L",
            "-p",
            proto,
        ],
        timeout=3,
    )

    return conntrack_original_match_text(
        event,
        raw,
    )


def socket_return_match(
    event: dict,
    *,
    identities: set[str],
) -> bool:

    ss_bin = shutil.which(
        "ss"
    )

    if not ss_bin:
        return False

    proto = str(
        event.get("protocol") or ""
    ).upper()

    if proto == "TCP":
        args = [
            ss_bin,
            "-H",
            "-t",
            "-n",
            "-p",
        ]

    elif proto == "UDP":
        args = [
            ss_bin,
            "-H",
            "-u",
            "-n",
            "-p",
        ]

    else:
        return False

    raw = _run(
        args
    )

    return socket_flow_match_text(
        event,
        local_ips=identities,
        raw=raw,
    )


def enrich_suricata_direction(
    event: dict,
) -> dict:

    result = dict(event)

    identities = local_ips()

    source_ip = str(
        result.get("source_ip") or ""
    )

    destination_ip = str(
        result.get("destination_ip") or ""
    )

    remote_to_local = (
        source_ip not in identities
        and destination_ip in identities
    )

    conntrack_match = False
    socket_match = False

    if remote_to_local:
        conntrack_match = (
            conntrack_return_match(
                result
            )
        )

        if not conntrack_match:
            socket_match = (
                socket_return_match(
                    result,
                    identities=identities,
                )
            )

    direction = classify_direction(
        result,
        local_ips=identities,
        conntrack_return=conntrack_match,
        socket_return=socket_match,
    )

    result.update(
        {
            "direction":
                direction.direction,

            "direction_evidence":
                direction.evidence,

            "self_originated":
                direction.self_originated,

            "return_traffic":
                direction.return_traffic,

            "locally_initiated_flow":
                direction.locally_initiated_flow,
        }
    )

    return result
