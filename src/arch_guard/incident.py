from __future__ import annotations

from pathlib import Path

from arch_guard.snapshot import (
    write_snapshot,
)


def create_incident_if_needed(
    event: dict,
    *,
    incident_dir: Path,
) -> tuple[
    Path,
    Path,
] | None:

    if event.get(
        "snapshot"
    ) is not True:
        return None

    return write_snapshot(
        event,
        incident_dir,
    )
