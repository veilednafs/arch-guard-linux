from __future__ import annotations

import json
from typing import Any

from arch_guard.events import make_event


def map_suricata_severity(
    value: Any,
) -> str:
    """
    Suricata severity:
      1 -> CRITICAL
      2 -> HIGH
      3 -> WARNING
      diğer -> INFO
    """

    try:
        severity = int(value)
    except (
        TypeError,
        ValueError,
    ):
        return "WARNING"

    if severity <= 1:
        return "CRITICAL"

    if severity == 2:
        return "HIGH"

    if severity == 3:
        return "WARNING"

    return "INFO"


def _signature_id(
    value: Any,
) -> int | str | None:

    if value is None:
        return None

    try:
        return int(value)
    except (
        TypeError,
        ValueError,
    ):
        return str(value)


def parse_suricata_alert(
    obj: dict[str, Any],
    *,
    sensor_profile: str = "default",
    event_timestamp: str | None = None,
) -> dict[str, Any] | None:

    if obj.get("event_type") != "alert":
        return None

    alert = obj.get("alert")

    if not isinstance(
        alert,
        dict,
    ):
        return None

    signature = str(
        alert.get("signature")
        or "Unknown IDS signature"
    )

    timestamp = (
        event_timestamp
        or obj.get("timestamp")
    )

    ether = obj.get("ether")

    if not isinstance(
        ether,
        dict,
    ):
        ether = {}

    source_ip = obj.get(
        "src_ip"
    )

    destination_ip = obj.get(
        "dest_ip"
    )

    source_port = obj.get(
        "src_port"
    )

    destination_port = obj.get(
        "dest_port"
    )

    return make_event(
        "suricata_alert",
        map_suricata_severity(
            alert.get("severity")
        ),
        sensor="suricata",
        notify=False,
        timestamp=timestamp,

        sensor_profile=str(
            sensor_profile
        ),

        signature=signature,

        signature_id=_signature_id(
            alert.get(
                "signature_id"
            )
        ),

        category=alert.get(
            "category"
        ),

        suricata_severity=alert.get(
            "severity"
        ),

        action=alert.get(
            "action"
        ),

        source_ip=source_ip,
        source_port=source_port,

        destination_ip=destination_ip,
        destination_port=destination_port,

        protocol=obj.get(
            "proto"
        ),

        app_proto=obj.get(
            "app_proto"
        ),

        flow_id=obj.get(
            "flow_id"
        ),

        community_id=obj.get(
            "community_id"
        ),

        in_interface=obj.get(
            "in_iface"
        ),

        # Ham L2 metadata.
        #
        # Bunları doğrudan source_mac /
        # destination_mac yapmıyoruz.
        # Özellikle uzak internet trafiğinde
        # src_mac gateway'e ait olabilir.
        ethernet_source_mac=ether.get(
            "src_mac"
        ),

        ethernet_destination_mac=ether.get(
            "dest_mac"
        ),
    )


def parse_eve_line(
    line: str,
    *,
    sensor_profile: str = "default",
) -> dict[str, Any] | None:

    try:
        obj = json.loads(
            line
        )
    except Exception:
        return None

    if not isinstance(
        obj,
        dict,
    ):
        return None

    return parse_suricata_alert(
        obj,
        sensor_profile=sensor_profile,
    )
