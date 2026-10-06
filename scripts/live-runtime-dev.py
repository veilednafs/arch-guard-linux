from __future__ import annotations

import argparse
import os

from pathlib import Path

from arch_guard.dispatcher import (
    EventDispatcher,
)
from arch_guard.live_runtime import (
    LiveRuntimeCoordinator,
)
from arch_guard.live_supervisor import (
    LiveSupervisor,
)
from arch_guard.runtime import (
    ArchGuardRuntime,
)


def restore_owner(
    root: Path,
) -> None:

    if os.geteuid() != 0:
        return

    uid_raw = os.environ.get(
        "SUDO_UID"
    )

    gid_raw = os.environ.get(
        "SUDO_GID"
    )

    if not uid_raw or not gid_raw:
        return

    try:
        uid = int(uid_raw)
        gid = int(gid_raw)
    except ValueError:
        return

    paths = [root]

    if root.exists():
        paths.extend(
            root.rglob("*")
        )

    for path in paths:
        try:
            os.chown(
                path,
                uid,
                gid,
            )
        except Exception:
            pass


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Arch Guard birleşik canlı "
            "development runtime"
        )
    )

    parser.add_argument(
        "--output-dir",
        default="var/live-runtime",
    )

    args = parser.parse_args()

    root = Path(
        args.output_dir
    )

    root.mkdir(
        parents=True,
        exist_ok=True,
    )

    dispatcher = EventDispatcher(
        event_log=(
            root
            / "events.jsonl"
        ),
        incident_dir=(
            root
            / "incidents"
        ),
    )

    runtime = ArchGuardRuntime(
        dispatcher
    )

    coordinator = (
        LiveRuntimeCoordinator(
            runtime
        )
    )

    supervisor = LiveSupervisor(
        coordinator
    )

    print()
    print(
        "Arch Guard development "
        "live runtime başladı."
    )

    print(
        "Çıkmak için Ctrl+C."
    )

    print(
        "Production servisleri "
        "değiştirilmiyor."
    )

    print()

    try:
        supervisor.run()

    finally:
        restore_owner(
            root
        )

    print()
    print(
        "========== ÖZET =========="
    )

    print(
        "SSH satırı       :",
        coordinator.stats.ssh_lines,
    )

    print(
        "SSH eventi       :",
        coordinator.stats.ssh_events,
    )

    print(
        "Network satırı   :",
        coordinator.stats.network_lines,
    )

    print(
        "Network eventi   :",
        coordinator.stats.network_events,
    )

    print(
        "Suricata satırı  :",
        coordinator.stats.suricata_lines,
    )

    print(
        "Suricata eventi  :",
        coordinator.stats.suricata_events,
    )

    print(
        "Tailscale satırı :",
        coordinator.stats.tailscale_lines,
    )

    print(
        "Tailscale eventi :",
        coordinator.stats.tailscale_events,
    )

    print(
        "Runtime received :",
        runtime.stats.received,
    )

    print(
        "Runtime logged   :",
        runtime.stats.logged,
    )

    print(
        "Incident         :",
        runtime.stats.incidents,
    )

    print(
        "Dispatch hatası  :",
        runtime.stats.dispatch_errors,
    )

    print(
        "Kaynak hatası    :",
        len(
            supervisor.source_errors
        ),
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
