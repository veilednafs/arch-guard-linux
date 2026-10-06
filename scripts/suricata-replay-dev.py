#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys

from collections import Counter
from pathlib import Path

from arch_guard.sensors.suricata import parse_eve_line
from arch_guard.suricata_direction import (
    REMOTE_INBOUND,
    classify_direction,
)
from arch_guard.suricata_direction_runtime import local_ips


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--profile",
        default="default",
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    args = parser.parse_args()

    identities = local_ips()
    output = Path(args.output)

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    counters = {
        "lines": 0,
        "alerts": 0,
    }

    severities = Counter()
    directions = Counter()
    signatures = Counter()
    sids = Counter()

    written = []

    with output.open(
        "w",
        encoding="utf-8",
    ) as target:

        for line in sys.stdin:
            counters["lines"] += 1

            event = parse_eve_line(
                line,
                sensor_profile=args.profile,
            )

            if event is None:
                continue

            counters["alerts"] += 1

            result = classify_direction(
                event,
                local_ips=identities,

                # Geçmiş kayıtta bugünkü conntrack/socket
                # durumunu kullanmıyoruz.
                conntrack_return=False,
                socket_return=False,
            )

            direction = result.direction

            # Geçmiş remote -> local trafik için
            # "gerçek inbound" ile "geri dönüş paketi"
            # ayrımını bugün kanıtlayamayız.
            if direction == REMOTE_INBOUND:
                direction = (
                    "REMOTE_TO_LOCAL_UNRESOLVED"
                )

                direction_evidence = (
                    "historical_ip_only"
                )

                return_state_unresolved = True

            else:
                direction_evidence = (
                    result.evidence
                )

                return_state_unresolved = False

            event["direction"] = direction

            event[
                "direction_evidence"
            ] = direction_evidence

            event[
                "return_state_unresolved"
            ] = return_state_unresolved

            event[
                "historical_replay"
            ] = True

            target.write(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )

            written.append(event)

            severities[
                event.get(
                    "severity",
                    "UNKNOWN",
                )
            ] += 1

            directions[
                direction
            ] += 1

            signature = str(
                event.get(
                    "signature"
                )
                or "UNKNOWN"
            )

            signatures[
                signature
            ] += 1

            sid = str(
                event.get(
                    "signature_id"
                )
                or "UNKNOWN"
            )

            sids[sid] += 1

    print()
    print("========================================")
    print(" SURICATA REPLAY SONUCU")
    print("========================================")

    print(
        "Profil              :",
        args.profile,
    )

    print(
        "Okunan EVE satırı   :",
        counters["lines"],
    )

    print(
        "Alert sayısı        :",
        counters["alerts"],
    )

    print(
        "Yerel IP sayısı     :",
        len(identities),
    )

    print()
    print("Severity dağılımı:")

    for name, count in severities.most_common():
        print(
            f"  {name:<24} {count}"
        )

    print()
    print("Yön dağılımı:")

    for name, count in directions.most_common():
        print(
            f"  {name:<32} {count}"
        )

    print()
    print("En sık 15 signature:")

    for name, count in signatures.most_common(15):
        print(
            f"  {count:>5}  {name}"
        )

    print()
    print("En sık 15 SID:")

    for sid, count in sids.most_common(15):
        print(
            f"  {count:>5}  {sid}"
        )

    print()
    print("Son 5 alert:")

    for event in written[-5:]:
        print()
        print(
            "  Zaman     :",
            event.get("timestamp"),
        )
        print(
            "  Seviye    :",
            event.get("severity"),
        )
        print(
            "  Yön       :",
            event.get("direction"),
        )
        print(
            "  SID       :",
            event.get("signature_id"),
        )
        print(
            "  Signature :",
            event.get("signature"),
        )
        print(
            "  Kaynak    :",
            (
                f"{event.get('source_ip')}:"
                f"{event.get('source_port')}"
            ),
        )
        print(
            "  Hedef     :",
            (
                f"{event.get('destination_ip')}:"
                f"{event.get('destination_port')}"
            ),
        )

    print()
    print(
        "Replay dosyası      :",
        output,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
