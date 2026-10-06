from __future__ import annotations

from collections.abc import Callable

from arch_guard.correlator import SSHCorrelator
from arch_guard.identity_runtime import enrich_ssh_identity
from arch_guard.policy import apply_policy
from arch_guard.sensors.ssh import parse_sshd_message


IdentityResolver = Callable[
    [dict],
    dict,
]


from arch_guard.faillock import FaillockDetector


class SSHPipeline:
    """
    SSH işlem zinciri:

    journal
      -> parser
      -> identity
      -> correlator
      -> policy
    """

    def __init__(
        self,
        correlator: SSHCorrelator | None = None,
        identity_resolver: IdentityResolver | None = None,
        lock_detector: FaillockDetector | None = None,
    ):
        self.correlator = (
            correlator
            if correlator is not None
            else SSHCorrelator()
        )

        self.identity_resolver = (
            identity_resolver
            if identity_resolver is not None
            else enrich_ssh_identity
        )

        self.lock_detector = lock_detector

    def process_message(
        self,
        message: str,
        *,
        now: float | None = None,
        event_timestamp: str | None = None,
    ) -> list[dict]:

        observed = parse_sshd_message(
            message,
            timestamp=event_timestamp,
        )

        if observed is None:
            return []

        observed = self.identity_resolver(
            observed
        )

        output = [
            apply_policy(observed)
        ]

        derived = self.correlator.process(
            observed,
            now=now,
        )

        for event in derived:
            output.append(
                apply_policy(event)
            )

        if self.lock_detector is not None:
            locked_events = self.lock_detector.process(
                observed
            )

            for event in locked_events:
                output.append(
                    apply_policy(event)
                )

        return output
