from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys

from collections import deque
from pathlib import Path

from . import __version__
from .config import (
    config_path,
    load_config,
)
from .daemon import run_daemon
from .notification_consumer import run_notifier


def _load_config(
    override: str | None,
):
    if override:
        return load_config(
            Path(override)
        )

    try:
        return load_config()

    except TypeError:
        return load_config(
            config_path()
        )


def _unit_state(
    unit: str,
    *,
    user: bool = False,
) -> str:

    command = [
        "systemctl",
    ]

    if user:
        command.append(
            "--user"
        )

    command += [
        "is-active",
        unit,
    ]

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return "unknown"

    state = (
        proc.stdout
        or ""
    ).strip()

    return (
        state
        or "inactive"
    )


def _yes_no(
    value: bool,
) -> str:

    return (
        "evet"
        if value
        else "hayır"
    )


def cmd_version(
    args,
) -> int:

    print(
        f"Arch Guard {__version__}"
    )

    return 0


def cmd_status(
    args,
) -> int:

    cfg = _load_config(
        args.config
    )

    event_log = Path(
        cfg.paths.event_log
    )

    incident_dir = Path(
        cfg.paths.incident_dir
    )

    try:
        cfg_path = (
            Path(args.config)
            if args.config
            else config_path()
        )
    except Exception:
        cfg_path = Path(
            "/etc/arch-guard/config.toml"
        )

    print(
        f"Arch Guard {__version__}"
    )

    print(
        f"Config       : {cfg_path}"
    )

    print(
        "SSH          :",
        "enabled"
        if cfg.ssh.enabled
        else "disabled",
    )

    print(
        "Network      :",
        "enabled"
        if cfg.network.enabled
        else "disabled",
    )

    print(
        "Suricata     :",
        "enabled"
        if cfg.suricata.enabled
        else "disabled",
    )

    print(
        "Tailscale scan :",
        "enabled"
        if cfg.tailscale_scan.enabled
        else "disabled",
    )

    print(
        f"Event log    : {event_log}"
    )

    print(
        "Event log var:",
        _yes_no(
            event_log.exists()
        ),
    )

    print(
        f"Incidents    : {incident_dir}"
    )

    print()
    print("Servisler:")

    print(
        "  arch-guard.service        :",
        _unit_state(
            "arch-guard.service"
        ),
    )

    print(
        "  arch-guard-notify.service :",
        _unit_state(
            "arch-guard-notify.service",
            user=True,
        ),
    )

    return 0


def _doctor_item(
    name: str,
    ok: bool,
    detail: str,
) -> bool:

    state = (
        "OK"
        if ok
        else "EKSİK"
    )

    print(
        f"{state:<5} "
        f"{name:<18} "
        f"{detail}"
    )

    return ok


def cmd_doctor(
    args,
) -> int:

    cfg = _load_config(
        args.config
    )

    failed = False

    print(
        f"Arch Guard {__version__} doctor"
    )

    print()

    required = {
        "journalctl":
            bool(
                cfg.ssh.enabled
                or cfg.network.enabled
            ),

        "ip":
            bool(
                cfg.network.enabled
                or cfg.ssh.enabled
            ),

        "ss":
            bool(
                cfg.network.enabled
                or cfg.ssh.enabled
                or cfg.suricata.enabled
            ),

        "tail":
            bool(
                cfg.suricata.enabled
            ),
    }

    for command, needed in required.items():
        path = shutil.which(
            command
        )

        ok = (
            path is not None
            or not needed
        )

        if needed and not ok:
            failed = True

        _doctor_item(
            command,
            ok,
            (
                path
                or (
                    "opsiyonel"
                    if not needed
                    else "bulunamadı"
                )
            ),
        )

    print()
    print("Opsiyonel / gelişmiş sensörler:")

    advanced = {
        "faillock": False,
        "tailscale": cfg.tailscale_scan.enabled,
        "tcpdump": cfg.tailscale_scan.enabled,
        "nft": cfg.network.enabled,
        "suricata": cfg.suricata.enabled,
        "notify-send": False,
    }

    for command, required_now in advanced.items():
        path = shutil.which(
            command
        )

        ok = (
            path is not None
            or not required_now
        )

        if required_now and not ok:
            failed = True

        _doctor_item(
            command,
            ok,
            (
                path
                or (
                    "opsiyonel"
                    if not required_now
                    else "bulunamadı"
                )
            ),
        )

    print()
    print("Dosya kontrolleri:")

    event_parent = Path(
        cfg.paths.event_log
    ).parent

    incident_parent = Path(
        cfg.paths.incident_dir
    )

    _doctor_item(
        "event-parent",
        (
            event_parent.exists()
            or event_parent.parent.exists()
        ),
        str(
            event_parent
        ),
    )

    _doctor_item(
        "incident-parent",
        (
            incident_parent.exists()
            or incident_parent.parent.exists()
        ),
        str(
            incident_parent
        ),
    )

    eve_files = [
        Path(path)
        for path in cfg.suricata.eve_files
    ]

    if cfg.suricata.enabled:
        for path in eve_files:
            exists = path.exists()

            if not exists:
                failed = True

            _doctor_item(
                "suricata-eve",
                exists,
                str(path),
            )

    print()

    if failed:
        print(
            "Sonuç: temel gereksinimlerden "
            "en az biri eksik."
        )

        return 1

    print(
        "Sonuç: temel kontroller geçti."
    )

    return 0


def _read_events(
    path: Path,
    *,
    limit: int,
    event_filter: str | None,
) -> list[dict]:

    if limit < 1:
        return []

    if not path.exists():
        return []

    selected: deque[
        dict
    ] = deque(
        maxlen=limit
    )

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:

        for line in handle:
            try:
                event = json.loads(
                    line
                )
            except Exception:
                continue

            if not isinstance(
                event,
                dict,
            ):
                continue

            if (
                event_filter
                and event.get("event")
                != event_filter
            ):
                continue

            selected.append(
                event
            )

    return list(
        selected
    )


def cmd_events(
    args,
) -> int:

    cfg = _load_config(
        args.config
    )

    path = Path(
        cfg.paths.event_log
    )

    events = _read_events(
        path,
        limit=args.limit,
        event_filter=args.event,
    )

    if args.json:
        print(
            json.dumps(
                events,
                ensure_ascii=False,
                indent=2,
            )
        )

        return 0

    if not events:
        print(
            "Event bulunamadı."
        )

        return 0

    for event in events:
        timestamp = event.get(
            "timestamp",
            "-",
        )

        severity = event.get(
            "severity",
            "-",
        )

        event_type = event.get(
            "event",
            "-",
        )

        sensor = event.get(
            "sensor",
            "-",
        )

        notify = event.get(
            "notify",
            False,
        )

        snapshot = event.get(
            "snapshot",
            False,
        )

        print(
            f"{timestamp} "
            f"{severity:<8} "
            f"{sensor:<15} "
            f"{event_type:<30} "
            f"notify={notify} "
            f"snapshot={snapshot}"
        )

    return 0


def cmd_run(
    args,
) -> int:

    cfg = _load_config(
        args.config
    )

    return run_daemon(
        cfg,
        enable_tailscale_scan=(
            args.tailscale_scan
        ),
    )


def cmd_notify(
    args,
) -> int:

    cfg = _load_config(
        args.config
    )

    return run_notifier(
        Path(
            cfg.paths.event_log
        ),
        from_start=args.from_start,
    )


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="arch-guard",
        description=(
            "Local-first host and network "
            "security monitor for Arch Linux"
        ),
    )

    parser.add_argument(
        "--config",
        help=(
            "TOML config dosyası "
            "(varsayılan sistem config'i)"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    run = subparsers.add_parser(
        "run",
        help="Arch Guard runtime'ını çalıştır",
    )

    run.add_argument(
        "--tailscale-scan",
        action="store_true",
        help=(
            "Tailscale userspace loopback "
            "scan sensörünü etkinleştir"
        ),
    )

    run.set_defaults(
        handler=cmd_run
    )

    notify = subparsers.add_parser(
        "notify",
        help=(
            "Kullanıcı masaüstü bildirim "
            "consumer'ını çalıştır"
        ),
    )

    notify.add_argument(
        "--from-start",
        action="store_true",
        help=(
            "Event logunu baştan oku "
            "(normal servis kullanımı için önerilmez)"
        ),
    )

    notify.set_defaults(
        handler=cmd_notify
    )

    version = subparsers.add_parser(
        "version",
        help="Sürümü göster",
    )

    version.set_defaults(
        handler=cmd_version
    )

    status = subparsers.add_parser(
        "status",
        help="Yerel durum özetini göster",
    )

    status.set_defaults(
        handler=cmd_status
    )

    doctor = subparsers.add_parser(
        "doctor",
        help="Bağımlılık ve kaynak kontrollerini yap",
    )

    doctor.set_defaults(
        handler=cmd_doctor
    )

    events = subparsers.add_parser(
        "events",
        help="Son Arch Guard eventlerini göster",
    )

    events.add_argument(
        "-n",
        "--limit",
        type=int,
        default=20,
        help="Gösterilecek son event sayısı",
    )

    events.add_argument(
        "--event",
        help="Yalnız bu event tipini göster",
    )

    events.add_argument(
        "--json",
        action="store_true",
        help="JSON çıktı üret",
    )

    events.set_defaults(
        handler=cmd_events
    )

    return parser


def main(
    argv: list[str] | None = None,
) -> int:

    parser = build_parser()

    args = parser.parse_args(
        argv
    )

    handler = getattr(
        args,
        "handler",
        None,
    )

    if handler is None:
        parser.print_help()
        return 0

    try:
        return int(
            handler(args)
        )

    except (
        OSError,
        ValueError,
        RuntimeError,
    ) as exc:

        print(
            f"HATA: {exc}",
            file=sys.stderr,
        )

        return 2
