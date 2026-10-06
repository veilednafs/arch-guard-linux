from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass


TAILSCALE_NET = ipaddress.ip_network(
    "100.64.0.0/10"
)


@dataclass(slots=True)
class NetworkIdentity:
    source_scope: str
    source_mac: str | None = None
    route_interface: str | None = None
    gateway: str | None = None
    neighbor_state: str | None = None
    attribution_confidence: str = "none"


def classify_source_ip(
    value: str,
) -> str:

    try:
        address = ipaddress.ip_address(
            value
        )
    except ValueError:
        return "unknown"

    if address.is_loopback:
        return "loopback"

    if (
        address.version == 4
        and address in TAILSCALE_NET
    ):
        return "tailscale"

    if address.is_global:
        return "public"

    if address.is_private:
        return "private"

    return "other"


def parse_route_json(
    raw: str,
) -> dict:

    try:
        data = json.loads(
            raw or "[]"
        )
    except Exception:
        return {}

    if (
        not isinstance(data, list)
        or not data
        or not isinstance(data[0], dict)
    ):
        return {}

    return data[0]


def parse_neighbor_json(
    raw: str,
    source_ip: str,
) -> dict:

    try:
        data = json.loads(
            raw or "[]"
        )
    except Exception:
        return {}

    if not isinstance(data, list):
        return {}

    for item in data:
        if not isinstance(item, dict):
            continue

        if str(
            item.get("dst")
        ) != source_ip:
            continue

        return item

    return {}


def _neighbor_state(
    neighbor: dict,
) -> str | None:

    state = neighbor.get(
        "state"
    )

    if isinstance(state, list):
        if not state:
            return None

        return ",".join(
            str(item)
            for item in state
        )

    if state is None:
        return None

    return str(state)


def _usable_neighbor_mac(
    neighbor: dict,
) -> str | None:

    mac = neighbor.get(
        "lladdr"
    )

    if not mac:
        return None

    state = (
        _neighbor_state(neighbor)
        or ""
    ).upper()

    if (
        "FAILED" in state
        or "INCOMPLETE" in state
    ):
        return None

    return str(mac).lower()


def resolve_network_identity(
    *,
    source_ip: str,
    route_json: str,
    neighbor_json: str,
) -> NetworkIdentity:

    ip_class = classify_source_ip(
        source_ip
    )

    route = parse_route_json(
        route_json
    )

    interface = route.get(
        "dev"
    )

    gateway = route.get(
        "gateway"
    )

    if ip_class == "unknown":
        return NetworkIdentity(
            source_scope="unknown",
            route_interface=interface,
            gateway=gateway,
        )

    if ip_class == "loopback":
        return NetworkIdentity(
            source_scope="loopback",
            route_interface=interface,
            gateway=gateway,
            attribution_confidence="direct",
        )

    # Tailscale adreslerinde ethernet/Wi-Fi MAC
    # anlamlı bir kaynak kimliği değildir.
    if ip_class == "tailscale":
        return NetworkIdentity(
            source_scope="tailscale",
            route_interface=interface,
            gateway=gateway,
            attribution_confidence="route",
        )

    # Uzak internet hostunun L2 MAC adresini
    # yerel makine göremez. Burada gateway MAC'i
    # asla source_mac olarak kullanılmaz.
    if ip_class == "public":
        return NetworkIdentity(
            source_scope="remote_public",
            source_mac=None,
            route_interface=interface,
            gateway=gateway,
            attribution_confidence="route",
        )

    if ip_class == "private":
        # Kaynağa ulaşmak için gateway gerekiyorsa
        # MAC doğrudan kaynağa ait kabul edilemez.
        if gateway:
            return NetworkIdentity(
                source_scope="private_routed",
                source_mac=None,
                route_interface=interface,
                gateway=gateway,
                attribution_confidence="route",
            )

        neighbor = parse_neighbor_json(
            neighbor_json,
            source_ip,
        )

        state = _neighbor_state(
            neighbor
        )

        mac = _usable_neighbor_mac(
            neighbor
        )

        if mac:
            return NetworkIdentity(
                source_scope="lan_direct",
                source_mac=mac,
                route_interface=interface,
                gateway=None,
                neighbor_state=state,
                attribution_confidence="neighbor",
            )

        return NetworkIdentity(
            source_scope="lan_unresolved",
            source_mac=None,
            route_interface=interface,
            gateway=None,
            neighbor_state=state,
            attribution_confidence="route",
        )

    return NetworkIdentity(
        source_scope="other",
        route_interface=interface,
        gateway=gateway,
        attribution_confidence="route",
    )
