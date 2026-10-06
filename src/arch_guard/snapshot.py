from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from datetime import datetime
from pathlib import Path
from typing import Any


def run_command(
    args: list[str],
    *,
    timeout: float = 8,
) -> dict[str, Any]:

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        return {
            "ok":
                proc.returncode == 0,

            "returncode":
                proc.returncode,

            "stdout":
                proc.stdout,

            "stderr":
                proc.stderr,
        }

    except Exception as exc:
        return {
            "ok":
                False,

            "returncode":
                -1,

            "stdout":
                "",

            "stderr":
                repr(exc),
        }


def safe_name(
    value: str,
) -> str:

    cleaned = re.sub(
        r"[^A-Za-z0-9_-]+",
        "_",
        str(value),
    )

    return (
        cleaned[:80]
        or "event"
    )


def listener_scope(
    local: str,
) -> str:

    value = str(local).strip()

    if (
        value.startswith("127.")
        or value.startswith("[::1]")
    ):
        return "loopback-only"

    if (
        value.startswith("0.0.0.0:")
        or value.startswith("[::]:")
        or value.startswith("*:")
    ):
        return "all-interfaces"

    return "bound-interface"


def get_listeners() -> list[dict]:

    ss = shutil.which("ss")

    if not ss:
        return []

    result = run_command(
        [
            ss,
            "-H",
            "-lntup",
        ]
    )

    listeners = []

    for line in result["stdout"].splitlines():
        parts = line.split(
            None,
            6,
        )

        if len(parts) < 6:
            continue

        local = parts[4]

        listeners.append(
            {
                "protocol":
                    parts[0],

                "state":
                    parts[1],

                "local":
                    local,

                "peer":
                    parts[5],

                "process":
                    (
                        parts[6]
                        if len(parts) >= 7
                        else ""
                    ),

                "scope":
                    listener_scope(
                        local
                    ),
            }
        )

    return listeners


def get_established() -> list[str]:

    ss = shutil.which("ss")

    if not ss:
        return []

    result = run_command(
        [
            ss,
            "-H",
            "-tnp",
            "state",
            "established",
        ]
    )

    return [
        line
        for line in result[
            "stdout"
        ].splitlines()
        if line.strip()
    ]


def get_interfaces() -> list:

    ip = shutil.which("ip")

    if not ip:
        return []

    result = run_command(
        [
            ip,
            "-j",
            "address",
            "show",
        ]
    )

    try:
        data = json.loads(
            result["stdout"]
            or "[]"
        )
    except Exception:
        return []

    return (
        data
        if isinstance(data, list)
        else []
    )


def get_neighbours() -> list[dict]:

    ip = shutil.which("ip")

    if not ip:
        return []

    result = run_command(
        [
            ip,
            "-j",
            "neigh",
            "show",
        ]
    )

    try:
        data = json.loads(
            result["stdout"]
            or "[]"
        )
    except Exception:
        return []

    output = []

    for item in data:
        if not isinstance(
            item,
            dict,
        ):
            continue

        output.append(
            {
                "ip":
                    item.get("dst"),

                "mac":
                    item.get(
                        "lladdr"
                    ),

                "interface":
                    item.get("dev"),

                "state":
                    item.get("state"),
            }
        )

    return output


def get_tailscale() -> dict:

    tailscale = shutil.which(
        "tailscale"
    )

    if not tailscale:
        return {
            "available": False,
            "self": {},
            "peers": [],
        }

    result = run_command(
        [
            tailscale,
            "status",
            "--json",
        ]
    )

    if not result["ok"]:
        return {
            "available": False,
            "self": {},
            "peers": [],
        }

    try:
        data = json.loads(
            result["stdout"]
        )
    except Exception:
        return {
            "available": False,
            "self": {},
            "peers": [],
        }

    self_raw = (
        data.get("Self")
        or {}
    )

    self_info = {
        "hostname":
            self_raw.get(
                "HostName"
            ),

        "dns_name":
            self_raw.get(
                "DNSName"
            ),

        "os":
            self_raw.get("OS"),

        "tailscale_ips":
            self_raw.get(
                "TailscaleIPs"
            )
            or [],

        "online":
            self_raw.get(
                "Online"
            ),
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

        peers.append(
            {
                "hostname":
                    peer.get(
                        "HostName"
                    ),

                "dns_name":
                    peer.get(
                        "DNSName"
                    ),

                "os":
                    peer.get("OS"),

                "tailscale_ips":
                    peer.get(
                        "TailscaleIPs"
                    )
                    or [],

                "online":
                    peer.get(
                        "Online"
                    ),

                "active":
                    peer.get(
                        "Active"
                    ),

                "last_seen":
                    peer.get(
                        "LastSeen"
                    ),
            }
        )

    return {
        "available": True,
        "self": self_info,
        "peers": peers,
    }


def get_recent_ssh() -> list[str]:

    journalctl = shutil.which(
        "journalctl"
    )

    if not journalctl:
        return []

    result = run_command(
        [
            journalctl,
            "-u",
            "sshd.service",
            "--since",
            "-10 min",
            "--no-pager",
            "-o",
            "short-iso",
        ]
    )

    return [
        line
        for line in result[
            "stdout"
        ].splitlines()
        if line.strip()
    ]


def get_nftables() -> str:

    nft = shutil.which("nft")

    if not nft:
        return ""

    result = run_command(
        [
            nft,
            "list",
            "ruleset",
        ],
        timeout=10,
    )

    return result["stdout"]


def collect_snapshot(
    trigger: dict,
) -> dict:

    return {
        "generated":
            datetime.now()
            .astimezone()
            .isoformat(
                timespec="seconds"
            ),

        "trigger":
            dict(trigger),

        "tailscale":
            get_tailscale(),

        "listeners":
            get_listeners(),

        "established":
            get_established(),

        "interfaces":
            get_interfaces(),

        "neighbours":
            get_neighbours(),

        "recent_ssh":
            get_recent_ssh(),

        "nftables":
            get_nftables(),
    }


def render_text(
    report: dict,
) -> str:

    event = (
        report.get("trigger")
        or {}
    )

    lines = [
        "=" * 72,
        "ARCH GUARD INCIDENT REPORT",
        "=" * 72,
        (
            "Generated : "
            + str(
                report.get(
                    "generated",
                    ""
                )
            )
        ),
        (
            "Event     : "
            + str(
                event.get(
                    "event",
                    "unknown",
                )
            )
        ),
        (
            "Severity  : "
            + str(
                event.get(
                    "severity",
                    "unknown",
                )
            )
        ),
        "",
        "---- TRIGGER ----",
    ]

    for key in (
        "source_ip",
        "source_mac",
        "source_scope",
        "user",
        "device",
        "platform",
        "transport",
        "direction",
        "signature_id",
        "signature",
        "failure_count",
        "ports",
        "correlation",
    ):
        if key in event:
            lines.append(
                f"{key:18}: "
                f"{event.get(key)}"
            )

    lines += [
        "",
        "---- TAILSCALE SELF ----",
    ]

    tailscale = (
        report.get("tailscale")
        or {}
    )

    if tailscale.get(
        "available"
    ):
        for key, value in (
            tailscale.get(
                "self"
            )
            or {}
        ).items():
            lines.append(
                f"{key:18}: {value}"
            )
    else:
        lines.append(
            "Tailscale unavailable"
        )

    lines += [
        "",
        "---- TAILSCALE PEERS ----",
    ]

    for peer in tailscale.get(
        "peers",
        [],
    ):
        lines.append(
            (
                f"{peer.get('hostname')} | "
                f"IPs={peer.get('tailscale_ips')} | "
                f"OS={peer.get('os')} | "
                f"online={peer.get('online')} | "
                f"active={peer.get('active')}"
            )
        )

    lines += [
        "",
        "---- LISTENING PORTS ----",
    ]

    for listener in report.get(
        "listeners",
        [],
    ):
        lines.append(
            (
                f"[{listener.get('scope')}] "
                f"{listener.get('protocol')} "
                f"{listener.get('local')} "
                f"{listener.get('process')}"
            )
        )

    lines += [
        "",
        "---- ESTABLISHED TCP ----",
    ]

    lines.extend(
        report.get(
            "established"
        )
        or ["none"]
    )

    lines += [
        "",
        "---- LAN NEIGHBOURS ----",
    ]

    for neighbour in report.get(
        "neighbours",
        [],
    ):
        lines.append(
            (
                f"IP={neighbour.get('ip')} "
                f"MAC={neighbour.get('mac')} "
                f"IF={neighbour.get('interface')} "
                f"STATE={neighbour.get('state')}"
            )
        )

    lines += [
        "",
        "---- RECENT SSH JOURNAL ----",
    ]

    lines.extend(
        report.get(
            "recent_ssh"
        )
        or ["none"]
    )

    lines += [
        "",
        "---- NFTABLES ----",
        str(
            report.get(
                "nftables",
                ""
            )
        ),
    ]

    return (
        "\n".join(lines)
        + "\n"
    )


def write_snapshot(
    trigger: dict,
    incident_dir: Path,
) -> tuple[
    Path,
    Path,
]:

    incident_dir = Path(
        incident_dir
    )

    incident_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = collect_snapshot(
        trigger
    )

    stamp = (
        datetime.now()
        .astimezone()
        .strftime(
            "%Y%m%d-%H%M%S-%f"
        )
    )

    base = (
        f"{stamp}-"
        f"{safe_name(trigger.get('event', 'event'))}"
    )

    json_path = (
        incident_dir
        / f"{base}.json"
    )

    text_path = (
        incident_dir
        / f"{base}.txt"
    )

    json_path.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    text_path.write_text(
        render_text(
            report
        ),
        encoding="utf-8",
    )

    os.chmod(
        json_path,
        0o640,
    )

    os.chmod(
        text_path,
        0o640,
    )

    return (
        json_path,
        text_path,
    )
