from __future__ import annotations

import queue
import shutil
import subprocess
import threading

from dataclasses import dataclass
from pathlib import Path

from arch_guard.live_runtime import (
    LiveRuntimeCoordinator,
)


@dataclass(frozen=True, slots=True)
class LiveSource:
    name: str
    kind: str
    command: tuple[str, ...]


@dataclass(slots=True)
class SourceMessage:
    source: LiveSource
    line: str | None = None
    returncode: int | None = None
    error: str | None = None


def default_sources(
    eve_path: str | Path = "/var/log/suricata/eve.json",
) -> list[LiveSource]:

    return [
        LiveSource(
            name="ssh-journal",
            kind="ssh",
            command=(
                "journalctl",
                "-f",
                "-n",
                "0",
                "-o",
                "json",
                "-u",
                "sshd.service",
            ),
        ),
        LiveSource(
            name="kernel-network",
            kind="network",
            command=(
                "journalctl",
                "-f",
                "-n",
                "0",
                "-o",
                "json",
                "-k",
            ),
        ),
        LiveSource(
            name="suricata-eve",
            kind="suricata",
            command=(
                "tail",
                "-n",
                "0",
                "-F",
                str(eve_path),
            ),
        ),
        LiveSource(
            name="tailscale-scan",
            kind="tailscale_scan",
            command=(
                "tcpdump",
                "-l",
                "-nn",
                "-i",
                "lo",
                "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn",
            ),
        ),
    ]


def validate_sources(
    sources: list[LiveSource],
) -> list[str]:

    errors: list[str] = []

    for source in sources:
        executable = source.command[0]

        if shutil.which(executable) is None:
            errors.append(
                f"{source.name}: "
                f"{executable!r} bulunamadı"
            )

    return errors


class LiveSupervisor:

    def __init__(
        self,
        coordinator: LiveRuntimeCoordinator,
        *,
        sources: list[LiveSource] | None = None,
    ):
        self.coordinator = coordinator

        self.sources = (
            list(sources)
            if sources is not None
            else default_sources()
        )

        self.stop_event = threading.Event()

        self.messages: queue.Queue[
            SourceMessage
        ] = queue.Queue()

        self.processes: dict[
            str,
            subprocess.Popen,
        ] = {}

        self.threads: list[
            threading.Thread
        ] = []

        self.source_errors: list[str] = []

    def dispatch_line(
        self,
        source: LiveSource,
        line: str,
    ) -> int:

        if source.kind == "ssh":
            return (
                self.coordinator
                .process_ssh_line(line)
            )

        if source.kind == "network":
            return (
                self.coordinator
                .process_network_line(line)
            )

        if source.kind == "suricata":
            return (
                self.coordinator
                .process_suricata_line(line)
            )

        if source.kind == "tailscale_scan":
            return (
                self.coordinator
                .process_tailscale_scan_line(line)
            )

        raise ValueError(
            f"Bilinmeyen kaynak tipi: "
            f"{source.kind!r}"
        )

    def _reader(
        self,
        source: LiveSource,
    ) -> None:

        try:
            proc = subprocess.Popen(
                list(source.command),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )

            self.processes[
                source.name
            ] = proc

        except Exception as exc:
            self.messages.put(
                SourceMessage(
                    source=source,
                    error=repr(exc),
                )
            )
            return

        assert proc.stdout is not None

        try:
            for line in proc.stdout:
                if self.stop_event.is_set():
                    break

                self.messages.put(
                    SourceMessage(
                        source=source,
                        line=line,
                    )
                )

        finally:
            returncode = proc.poll()

            self.messages.put(
                SourceMessage(
                    source=source,
                    returncode=returncode,
                )
            )

    def start(self) -> None:

        errors = validate_sources(
            self.sources
        )

        if errors:
            raise RuntimeError(
                "; ".join(errors)
            )

        for source in self.sources:
            thread = threading.Thread(
                target=self._reader,
                args=(source,),
                name=(
                    "arch-guard-"
                    + source.name
                ),
                daemon=True,
            )

            self.threads.append(
                thread
            )

            thread.start()

    def stop(self) -> None:

        self.stop_event.set()

        for proc in list(
            self.processes.values()
        ):
            if proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass

        for proc in list(
            self.processes.values()
        ):
            if proc.poll() is None:
                try:
                    proc.wait(
                        timeout=2
                    )
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

        for thread in self.threads:
            thread.join(
                timeout=2
            )

    def run(self) -> None:

        self.start()

        try:
            while not self.stop_event.is_set():

                try:
                    message = self.messages.get(
                        timeout=0.5
                    )
                except queue.Empty:
                    continue

                if message.error:
                    error = (
                        f"{message.source.name}: "
                        f"{message.error}"
                    )

                    self.source_errors.append(
                        error
                    )

                    print(
                        "[KAYNAK HATASI]",
                        error,
                        flush=True,
                    )

                    continue

                if message.line is not None:
                    try:
                        emitted = self.dispatch_line(
                            message.source,
                            message.line,
                        )

                        if emitted:
                            print(
                                f"[{message.source.kind}] "
                                f"{emitted} event",
                                flush=True,
                            )

                    except Exception as exc:
                        error = (
                            f"{message.source.name}: "
                            f"{exc!r}"
                        )

                        self.source_errors.append(
                            error
                        )

                        print(
                            "[İŞLEME HATASI]",
                            error,
                            flush=True,
                        )

                    continue

                if (
                    message.returncode is not None
                    and not self.stop_event.is_set()
                ):
                    error = (
                        f"{message.source.name} "
                        f"beklenmedik şekilde kapandı "
                        f"(rc={message.returncode})"
                    )

                    self.source_errors.append(
                        error
                    )

                    print(
                        "[KAYNAK KAPANDI]",
                        error,
                        flush=True,
                    )

        except KeyboardInterrupt:
            print(
                "\nCtrl+C alındı; "
                "kaynaklar kapatılıyor...",
                flush=True,
            )

        finally:
            self.stop()
