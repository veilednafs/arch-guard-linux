from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from arch_guard.events import EventWriter
from arch_guard.incident import create_incident_if_needed


@dataclass(slots=True)
class DispatchResult:
    logged: bool = False
    incident_created: bool = False
    incident_paths: tuple[Path, Path] | None = None
    errors: list[str] = field(default_factory=list)


class EventDispatcher:
    """
    Privileged Arch Guard output boundary.

    Görevleri:
      1. Her normalize edilmiş eventi JSONL loguna yazmak.
      2. Yalnız snapshot=True ise incident üretmek.

    Desktop notification burada yapılmaz.

    notify=True alanı event içinde korunur ve kullanıcı
    oturumundaki notifier consumer tarafından işlenir.
    """

    def __init__(
        self,
        *,
        event_log: Path,
        incident_dir: Path,
    ):
        self.writer = EventWriter(
            Path(event_log)
        )

        self.incident_dir = Path(
            incident_dir
        )

    def dispatch(
        self,
        event: dict,
    ) -> DispatchResult:

        result = DispatchResult()

        try:
            self.writer.write(
                event
            )

            result.logged = True

        except Exception as exc:
            result.errors.append(
                f"event_log: {exc!r}"
            )

            # Log yazılamadıysa event zincirini burada
            # bitirmiyoruz; kritik snapshot yine denenebilir.

        if event.get("snapshot") is True:
            try:
                paths = create_incident_if_needed(
                    event,
                    incident_dir=self.incident_dir,
                )

                if paths is not None:
                    result.incident_created = True
                    result.incident_paths = paths

            except Exception as exc:
                result.errors.append(
                    f"snapshot: {exc!r}"
                )

        return result
