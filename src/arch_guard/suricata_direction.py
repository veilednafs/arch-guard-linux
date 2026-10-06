from __future__ import annotations

import re
from dataclasses import dataclass


SELF_OUTBOUND = "SELF_OUTBOUND"
RETURN_TRAFFIC = "RETURN_TRAFFIC"
REMOTE_INBOUND = "REMOTE_INBOUND"
TRANSIT_OR_UNKNOWN = "TRANSIT_OR_UNKNOWN"


@dataclass(slots=True)
class DirectionResult:
    direction: str
    evidence: str

    @property
    def self_originated(self) -> bool:
        return self.direction == SELF_OUTBOUND

    @property
    def return_traffic(self) -> bool:
        return self.direction == RETURN_TRAFFIC

    @property
    def locally_initiated_flow(self) -> bool:
        return self.direction in {
            SELF_OUTBOUND,
            RETURN_TRAFFIC,
        }


def classify_direction(
    event: dict,
    *,
    local_ips: set[str],
    conntrack_return: bool = False,
    socket_return: bool = False,
) -> DirectionResult:

    source_ip = str(
        event.get("source_ip") or ""
    )

    destination_ip = str(
        event.get("destination_ip") or ""
    )

    if source_ip in local_ips:
        return DirectionResult(
            direction=SELF_OUTBOUND,
            evidence="local_source_ip",
        )

    if destination_ip in local_ips:
        if conntrack_return:
            return DirectionResult(
                direction=RETURN_TRAFFIC,
                evidence="conntrack_original_tuple",
            )

        if socket_return:
            return DirectionResult(
                direction=RETURN_TRAFFIC,
                evidence="matching_local_socket",
            )

        return DirectionResult(
            direction=REMOTE_INBOUND,
            evidence="local_destination_ip",
        )

    return DirectionResult(
        direction=TRANSIT_OR_UNKNOWN,
        evidence="no_local_ip_endpoint",
    )


def conntrack_original_match_text(
    event: dict,
    raw: str,
) -> bool:

    proto = str(
        event.get("protocol") or ""
    ).lower()

    if proto not in {
        "tcp",
        "udp",
    }:
        return False

    source_ip = str(
        event.get("source_ip") or ""
    )

    destination_ip = str(
        event.get("destination_ip") or ""
    )

    try:
        source_port = int(
            event.get("source_port")
        )

        destination_port = int(
            event.get("destination_port")
        )

    except (
        TypeError,
        ValueError,
    ):
        return False

    pattern = re.compile(
        r"\bsrc=(\S+)\s+"
        r"dst=(\S+)\s+"
        r"sport=(\d+)\s+"
        r"dport=(\d+)"
    )

    for line in raw.splitlines():
        match = pattern.search(
            line
        )

        if not match:
            continue

        (
            original_source,
            original_destination,
            original_source_port,
            original_destination_port,
        ) = match.groups()

        # Suricata olayı remote -> local görünüyorsa,
        # conntrack'in ORIGINAL tuple'ı bunun ters
        # yönünde local -> remote olmalıdır.
        if (
            original_source == destination_ip
            and original_destination == source_ip
            and int(original_source_port)
            == destination_port
            and int(original_destination_port)
            == source_port
        ):
            return True

    return False


def endpoint_tokens(
    ip: str,
    port: int | str | None,
) -> set[str]:

    if not ip or port is None:
        return set()

    return {
        f"{ip}:{port}",
        f"[{ip}]:{port}",
    }


def socket_flow_match_text(
    event: dict,
    *,
    local_ips: set[str],
    raw: str,
) -> bool:

    source_ip = str(
        event.get("source_ip") or ""
    )

    destination_ip = str(
        event.get("destination_ip") or ""
    )

    source_port = event.get(
        "source_port"
    )

    destination_port = event.get(
        "destination_port"
    )

    if source_ip in local_ips:
        local_ip = source_ip
        local_port = source_port
        remote_ip = destination_ip
        remote_port = destination_port

    elif destination_ip in local_ips:
        local_ip = destination_ip
        local_port = destination_port
        remote_ip = source_ip
        remote_port = source_port

    else:
        return False

    local_tokens = endpoint_tokens(
        local_ip,
        local_port,
    )

    remote_tokens = endpoint_tokens(
        remote_ip,
        remote_port,
    )

    for line in raw.splitlines():
        if (
            any(
                token in line
                for token in local_tokens
            )
            and any(
                token in line
                for token in remote_tokens
            )
        ):
            return True

    return False
