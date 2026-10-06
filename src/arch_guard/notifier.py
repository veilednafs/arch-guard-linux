from __future__ import annotations

import shutil
import subprocess

from dataclasses import dataclass
from typing import Callable


TIMEOUTS = {
    "INFO": 4,
    "WARNING": 6,
    "HIGH": 8,
    "CRITICAL": 10,
}

URGENCIES = {
    "INFO": "low",
    "WARNING": "normal",
    "HIGH": "normal",
    "CRITICAL": "normal",
}


@dataclass(slots=True)
class Notification:
    title: str
    body: str
    severity: str
    timeout_seconds: int
    urgency: str


def _source(event: dict) -> str:
    return str(
        event.get("real_source_ip")
        or event.get("source_ip")
        or event.get("ssh_source_ip")
        or "unknown"
    )


def render_notification(
    event: dict,
) -> Notification | None:

    if event.get("notify") is not True:
        return None

    event_type = str(
        event.get("event")
        or "event"
    )

    severity = str(
        event.get(
            "severity",
            "WARNING",
        )
    ).upper()

    if severity not in TIMEOUTS:
        severity = "WARNING"

    title: str
    body: str

    if event_type == "ssh_auth_success":
        title = "ARCH GUARD — REMOTE ACCESS"

        body = (
            f"Kullanıcı: {event.get('user', 'unknown')}\n"
            f"Kaynak: {_source(event)}\n"
            f"Taşıma: {event.get('transport', 'direct')}\n"
            f"Cihaz: {event.get('device', 'unknown')}\n"
            f"Auth: {event.get('auth_method', 'unknown')}\n"
            "Sonuç: ACCESS GRANTED"
        )

    elif event_type == "ssh_account_locked":
        title = "ARCH GUARD — ACCOUNT LOCKED"

        body = (
            "PAM faillock koruması devreye girdi\n"
            f"Kullanıcı: {event.get('user', 'unknown')}\n"
            f"Kaynak: {_source(event)}\n"
            f"Başarısız kayıt: {event.get('pam_failure_count', '?')}\n"
            "Durum: ACCOUNT LOCKED"
        )

    elif event_type == "ssh_bruteforce":
        title = (
            "ARCH GUARD — BRUTE FORCE CRITICAL"
            if severity == "CRITICAL"
            else "ARCH GUARD — BRUTE FORCE"
        )

        users = event.get(
            "attempted_users"
        ) or []

        body = (
            f"Kaynak: {_source(event)}\n"
            f"Deneme: {event.get('failure_count', '?')} / "
            f"{event.get('window_seconds', '?')} sn\n"
            f"Kullanıcılar: {', '.join(map(str, users)) or 'unknown'}\n"
            "Sonuç: ACCESS DENIED"
        )

    elif event_type == "ssh_success_after_failures":
        title = "ARCH GUARD — SUSPICIOUS LOGIN"

        body = (
            f"Kullanıcı: {event.get('user', 'unknown')}\n"
            f"Kaynak: {_source(event)}\n"
            f"Önceki hata: {event.get('failure_count', '?')}\n"
            "Sonuç: ACCESS GRANTED"
        )

    elif event_type == "tailscale_port_scan":
        title = "ARCH GUARD — TAILSCALE PORT SCAN"

        ports = (
            event.get("ports")
            or []
        )

        body = (
            "Tailscale userspace üzerinden çoklu port taraması algılandı\n"
            f"Cihaz: {event.get('device', 'unknown')}\n"
            f"Kaynak: {_source(event)}\n"
            f"Platform: {event.get('platform', 'unknown')}\n"
            f"Kimlik güveni: {event.get('attribution_confidence', 'none')}\n"
            f"Port sayısı: {event.get('unique_ports', len(ports))} / "
            f"{event.get('window_seconds', '?')} sn\n"
            f"Portlar: {','.join(map(str, ports[:20]))}"
        )

    elif event_type == "network_port_scan":
        title = "ARCH GUARD — PORT SCAN"

        mac = (
            event.get("source_mac")
            or "N/A (remote host)"
        )

        ports = event.get(
            "ports"
        ) or []

        body = (
            "Çoklu port taraması algılandı\n"
            f"Kaynak: {_source(event)}\n"
            f"MAC: {mac}\n"
            f"Taşıma: {event.get('transport', 'unknown')}\n"
            f"Port sayısı: {event.get('unique_ports', len(ports))} / "
            f"{event.get('window_seconds', '?')} sn\n"
            f"Portlar: {','.join(map(str, ports[:20]))}"
        )

    elif event_type == "suricata_alert":
        direction = str(
            event.get(
                "direction",
                "UNKNOWN",
            )
        )

        if direction == "SELF_OUTBOUND":
            title = "ARCH GUARD — SELF/OUTBOUND IDS"

        elif direction == "RETURN_TRAFFIC":
            title = "ARCH GUARD — RETURN TRAFFIC IDS"

        else:
            title = "ARCH GUARD — IDS ALERT"

        body = (
            f"{event.get('signature', 'Unknown IDS signature')}\n"
            f"Yön: {direction}\n"
            f"Kaynak: {event.get('source_ip', 'unknown')}:"
            f"{event.get('source_port', 'unknown')}\n"
            f"Hedef: {event.get('destination_ip', 'unknown')}:"
            f"{event.get('destination_port', 'unknown')}\n"
            f"Protokol: {event.get('protocol', 'unknown')}\n"
            f"SID: {event.get('signature_id', 'unknown')}"
        )

    else:
        title = (
            "ARCH GUARD — "
            + event_type
            .replace("_", " ")
            .upper()
        )

        body = (
            f"Seviye: {severity}\n"
            f"Kaynak: {_source(event)}"
        )

    return Notification(
        title=title,
        body=body,
        severity=severity,
        timeout_seconds=TIMEOUTS[
            severity
        ],
        urgency=URGENCIES[
            severity
        ],
    )


class NotifySendBackend:
    """
    notify-send backend.

    İlk bildirimin ID'sini alır.
    Sonraki bildirimlerde aynı ID'yi replace ederek
    masaüstünde tek aktif Arch Guard toast'ı tutar.
    """

    def __init__(
        self,
        *,
        binary: str | None = None,
        runner: Callable = subprocess.run,
    ):
        self.binary = (
            binary
            or shutil.which("notify-send")
        )

        self.runner = runner
        self.notification_id: int | None = None

    @property
    def available(self) -> bool:
        return bool(
            self.binary
        )

    def send(
        self,
        notification: Notification,
    ) -> bool:

        if not self.binary:
            return False

        command = [
            self.binary,
            "-a",
            "Arch Guard",
            "-h",
            "string:desktop-entry:arch-guard",
            "-u",
            notification.urgency,
            "-t",
            str(
                notification.timeout_seconds
                * 1000
            ),
            "-p",
        ]

        if self.notification_id is not None:
            command += [
                "-r",
                str(
                    self.notification_id
                ),
            ]

        command += [
            notification.title,
            notification.body,
        ]

        try:
            proc = self.runner(
                command,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            return False

        if proc.returncode != 0:
            return False

        output = (
            proc.stdout
            or ""
        ).strip()

        try:
            notification_id = int(
                output.splitlines()[-1]
            )

            if notification_id > 0:
                self.notification_id = (
                    notification_id
                )

        except (
            ValueError,
            IndexError,
        ):
            pass

        return True


def notify_event(
    event: dict,
    backend: NotifySendBackend,
) -> bool:

    notification = render_notification(
        event
    )

    if notification is None:
        return False

    return backend.send(
        notification
    )
