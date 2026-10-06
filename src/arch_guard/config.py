from __future__ import annotations

import os
import tomllib

from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_CONFIG = Path("/etc/arch-guard/config.toml")


@dataclass(slots=True)
class PathsConfig:
    event_log: Path = Path("/var/log/arch-guard/events.jsonl")
    incident_dir: Path = Path("/var/log/arch-guard/incidents")


@dataclass(slots=True)
class SSHConfig:
    enabled: bool = True
    service: str = "sshd.service"
    brute_force_window: int = 60
    high_threshold: int = 3
    critical_threshold: int = 5


@dataclass(slots=True)
class NetworkConfig:
    enabled: bool = True
    port_scan_window: int = 10
    port_scan_threshold: int = 6
    cooldown: int = 60


@dataclass(slots=True)
class TailscaleScanConfig:
    enabled: bool = False
    window: int = 10
    threshold: int = 25
    cooldown: int = 60


@dataclass(slots=True)
class SuricataConfig:
    enabled: bool = True
    eve_files: list[str] = field(
        default_factory=lambda: [
            "/var/log/suricata/eve.json"
        ]
    )
    dedup_seconds: int = 30


@dataclass(slots=True)
class Config:
    paths: PathsConfig = field(default_factory=PathsConfig)
    ssh: SSHConfig = field(default_factory=SSHConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    tailscale_scan: TailscaleScanConfig = field(default_factory=TailscaleScanConfig)
    suricata: SuricataConfig = field(default_factory=SuricataConfig)


def config_path() -> Path:
    override = os.environ.get("ARCH_GUARD_CONFIG")

    if override:
        return Path(override).expanduser()

    return DEFAULT_CONFIG


def load_config(path: Path | None = None) -> Config:
    path = path or config_path()

    raw = {}

    if path.exists():
        with path.open("rb") as f:
            raw = tomllib.load(f)

    p = raw.get("paths", {})
    ssh = raw.get("ssh", {})
    net = raw.get("network", {})
    ts_scan = raw.get("tailscale_scan", {})
    suri = raw.get("suricata", {})

    return Config(
        paths=PathsConfig(
            event_log=Path(
                p.get(
                    "event_log",
                    "/var/log/arch-guard/events.jsonl",
                )
            ),
            incident_dir=Path(
                p.get(
                    "incident_dir",
                    "/var/log/arch-guard/incidents",
                )
            ),
        ),
        ssh=SSHConfig(
            enabled=bool(
                ssh.get("enabled", True)
            ),
            service=str(
                ssh.get("service", "sshd.service")
            ),
            brute_force_window=int(
                ssh.get("brute_force_window", 60)
            ),
            high_threshold=int(
                ssh.get("high_threshold", 3)
            ),
            critical_threshold=int(
                ssh.get("critical_threshold", 5)
            ),
        ),
        network=NetworkConfig(
            enabled=bool(
                net.get("enabled", True)
            ),
            port_scan_window=int(
                net.get("port_scan_window", 10)
            ),
            port_scan_threshold=int(
                net.get("port_scan_threshold", 6)
            ),
            cooldown=int(
                net.get("cooldown", 60)
            ),
        ),
        tailscale_scan=TailscaleScanConfig(
            enabled=bool(
                ts_scan.get("enabled", False)
            ),
            window=int(
                ts_scan.get("window", 10)
            ),
            threshold=int(
                ts_scan.get("threshold", 25)
            ),
            cooldown=int(
                ts_scan.get("cooldown", 60)
            ),
        ),
        suricata=SuricataConfig(
            enabled=bool(
                suri.get("enabled", True)
            ),
            eve_files=list(
                suri.get(
                    "eve_files",
                    ["/var/log/suricata/eve.json"],
                )
            ),
            dedup_seconds=int(
                suri.get("dedup_seconds", 30)
            ),
        ),
    )
