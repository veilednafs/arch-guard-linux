from __future__ import annotations

import json
import shutil
import subprocess

from arch_guard.network_identity import (
    NetworkIdentity,
    resolve_network_identity,
)


def _run(
    args: list[str],
) -> str:

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return ""

    if proc.returncode != 0:
        return ""

    return proc.stdout


def lookup_network_identity(
    source_ip: str,
) -> NetworkIdentity:

    ip_bin = shutil.which(
        "ip"
    )

    if not ip_bin:
        return NetworkIdentity(
            source_scope="unknown"
        )

    route_json = _run(
        [
            ip_bin,
            "-j",
            "route",
            "get",
            source_ip,
        ]
    )

    neighbor_json = _run(
        [
            ip_bin,
            "-j",
            "neigh",
            "show",
            "to",
            source_ip,
        ]
    )

    return resolve_network_identity(
        source_ip=source_ip,
        route_json=route_json,
        neighbor_json=neighbor_json,
    )


def enrich_network_identity(
    event: dict,
) -> dict:

    result = dict(event)

    source_ip = result.get(
        "source_ip"
    )

    if not source_ip:
        return result

    identity = lookup_network_identity(
        str(source_ip)
    )

    result.update(
        {
            "source_scope":
                identity.source_scope,

            "source_mac":
                identity.source_mac,

            "route_interface":
                identity.route_interface,

            "gateway":
                identity.gateway,

            "neighbor_state":
                identity.neighbor_state,

            "attribution_confidence":
                identity.attribution_confidence,
        }
    )

    return result
