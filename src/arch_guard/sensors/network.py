from __future__ import annotations

import re
from typing import Any

from arch_guard.events import make_event


FIELD_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]*)=([^\s]+)"
)


def _capture_profile(line: str) -> str | None:
    """
    Legacy nft prefixlerini ve gelecekte kullanılacak
    generic prefixi tanır.
    """

    if "AGNET_WLAN " in line:
        return "wlan"

    if "AGNET_WARP " in line:
        return "warp"

    if "AGNET " in line:
        return "generic"

    return None


def parse_nft_log_line(
    line: str,
    *,
    timestamp: str | None = None,
) -> dict[str, Any] | None:

    profile = _capture_profile(line)

    if profile is None:
        return None

    fields = dict(
        FIELD_RE.findall(line)
    )

    if fields.get("PROTO") != "TCP":
        return None

    source_ip = fields.get("SRC")
    destination_ip = fields.get("DST")

    if not source_ip or not destination_ip:
        return None

    try:
        source_port = int(
            fields["SPT"]
        )

        destination_port = int(
            fields["DPT"]
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return None

    interface = fields.get("IN")

    # Bunlar legacy uyumluluk alanlarıdır.
    # Public nft configine geçtiğimizde profile
    # isimleri interface hardcode'undan ayrılacak.
    if profile == "wlan":
        transport = "WLAN"

    elif profile == "warp":
        transport = "WARP"

    else:
        transport = "GENERIC"

    return make_event(
        "network_probe",
        "WARNING",
        sensor="nftables",
        notify=False,
        timestamp=timestamp,

        source_ip=source_ip,
        source_port=source_port,

        destination_ip=destination_ip,
        destination_port=destination_port,

        interface=interface,
        transport=transport,
        capture_profile=profile,

        protocol="TCP",
        raw=line,
    )
