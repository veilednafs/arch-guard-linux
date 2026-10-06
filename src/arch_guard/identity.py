from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class TailscalePeer:
    device: str
    source_ip: str
    platform: str
    online: bool
    active: bool


@dataclass(slots=True)
class IdentityResult:
    device: str = "unknown"
    source_ip: str = "unknown"
    platform: str = "unknown"
    identity_scope: str = "unresolved"
    confidence: str = "none"


def parse_tailscale_status(
    raw: str,
) -> list[TailscalePeer]:

    try:
        data = json.loads(raw or "{}")
    except Exception:
        return []

    peers: list[TailscalePeer] = []

    for peer in (data.get("Peer") or {}).values():
        if not isinstance(peer, dict):
            continue

        if peer.get("Online") is not True:
            continue

        ips = peer.get("TailscaleIPs") or []

        ipv4 = next(
            (
                str(ip)
                for ip in ips
                if "." in str(ip)
            ),
            None,
        )

        first_ip = (
            ipv4
            or (
                str(ips[0])
                if ips
                else "unknown"
            )
        )

        name = (
            peer.get("HostName")
            or peer.get("DNSName")
            or "unknown"
        )

        peers.append(
            TailscalePeer(
                device=str(name).rstrip("."),
                source_ip=first_ip,
                platform=str(
                    peer.get("OS") or "unknown"
                ),
                online=True,
                active=bool(
                    peer.get("Active")
                ),
            )
        )

    return peers


def choose_tailscale_peer(
    peers: list[TailscalePeer],
) -> IdentityResult:

    active = [
        peer
        for peer in peers
        if peer.active
    ]

    if len(active) == 1:
        peer = active[0]

        return IdentityResult(
            device=peer.device,
            source_ip=peer.source_ip,
            platform=peer.platform,
            identity_scope="unique_active_peer",
            confidence="heuristic",
        )

    if len(peers) == 1:
        peer = peers[0]

        return IdentityResult(
            device=peer.device,
            source_ip=peer.source_ip,
            platform=peer.platform,
            identity_scope="unique_online_peer",
            confidence="heuristic",
        )

    if not peers:
        return IdentityResult(
            identity_scope="no_online_peers",
        )

    return IdentityResult(
        device="ambiguous",
        identity_scope=(
            f"{len(peers)}_online_peers"
        ),
        confidence="none",
    )


def socket_owned_by_tailscale(
    ss_output: str,
    source_port: int,
) -> bool:

    needle = f"127.0.0.1:{int(source_port)}"

    for line in ss_output.splitlines():
        if needle not in line:
            continue

        if "tailscaled" in line.lower():
            return True

    return False


def resolve_ssh_identity(
    *,
    ssh_source_ip: str,
    ssh_source_port: int | None,
    ss_output: str,
    tailscale_status_json: str,
) -> dict[str, Any]:

    result: dict[str, Any] = {
        "transport": "direct",
        "real_source_ip": ssh_source_ip,
        "device": "unknown",
        "platform": "unknown",
        "identity_scope": "direct",
        "attribution_confidence": "direct",
    }

    if ssh_source_ip != "127.0.0.1":
        return result

    result["identity_scope"] = (
        "loopback_unattributed"
    )

    result["attribution_confidence"] = (
        "none"
    )

    if ssh_source_port is None:
        return result

    if not socket_owned_by_tailscale(
        ss_output,
        ssh_source_port,
    ):
        return result

    result["transport"] = (
        "tailscale/userspace-proxy"
    )

    peers = parse_tailscale_status(
        tailscale_status_json
    )

    identity = choose_tailscale_peer(
        peers
    )

    result.update(
        {
            "real_source_ip":
                identity.source_ip,

            "device":
                identity.device,

            "platform":
                identity.platform,

            "identity_scope":
                identity.identity_scope,

            "attribution_confidence":
                identity.confidence,
        }
    )

    return result
