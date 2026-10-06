from __future__ import annotations

import shutil
import subprocess

from arch_guard.identity import resolve_ssh_identity


def _run(
    args: list[str],
    timeout: float = 4,
) -> str:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception:
        return ""

    if proc.returncode != 0:
        return ""

    return proc.stdout


def enrich_ssh_identity(
    event: dict,
) -> dict:
    """
    SSH auth olayını canlı ağ kimliğiyle zenginleştirir.

    Kimlik çözülemezse olay bozulmaz.
    Tahmin edilen cihaz adı üretilmez.
    """

    result = dict(event)

    event_type = result.get("event")

    if event_type not in {
        "ssh_auth_success",
        "ssh_auth_failure",
        "ssh_invalid_user",
    }:
        return result

    source_ip = result.get(
        "ssh_source_ip"
    )

    if not source_ip:
        return result

    source_port = result.get(
        "ssh_source_port"
    )

    ss_bin = shutil.which("ss")

    ss_output = ""

    if ss_bin:
        ss_output = _run(
            [
                ss_bin,
                "-Htnp",
            ]
        )

    tailscale_json = ""

    tailscale_bin = shutil.which(
        "tailscale"
    )

    if tailscale_bin:
        tailscale_json = _run(
            [
                tailscale_bin,
                "status",
                "--json",
            ]
        )

    identity = resolve_ssh_identity(
        ssh_source_ip=str(source_ip),
        ssh_source_port=(
            int(source_port)
            if source_port is not None
            else None
        ),
        ss_output=ss_output,
        tailscale_status_json=tailscale_json,
    )

    result.update(identity)

    return result
