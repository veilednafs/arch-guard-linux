from __future__ import annotations

from collections.abc import Callable

from arch_guard.network_correlator import (
    NetworkScanCorrelator,
)
from arch_guard.network_identity_runtime import (
    enrich_network_identity,
)
from arch_guard.network_listener_runtime import (
    enrich_listener,
)
from arch_guard.policy import apply_policy
from arch_guard.sensors.network import (
    parse_nft_log_line,
)


Resolver = Callable[
    [dict],
    dict,
]


class NetworkPipeline:
    """
    nft/kernel işlem zinciri:

    parser
      -> identity
      -> listener
      -> scan correlator
      -> policy
    """

    def __init__(
        self,
        correlator: NetworkScanCorrelator | None = None,
        identity_resolver: Resolver | None = None,
        listener_resolver: Resolver | None = None,
    ):
        self.correlator = (
            correlator
            if correlator is not None
            else NetworkScanCorrelator()
        )

        self.identity_resolver = (
            identity_resolver
            if identity_resolver is not None
            else enrich_network_identity
        )

        self.listener_resolver = (
            listener_resolver
            if listener_resolver is not None
            else enrich_listener
        )

    def process_message(
        self,
        message: str,
        *,
        now: float | None = None,
        event_timestamp: str | None = None,
    ) -> list[dict]:

        observed = parse_nft_log_line(
            message,
            timestamp=event_timestamp,
        )

        if observed is None:
            return []

        observed = self.identity_resolver(
            observed
        )

        observed = self.listener_resolver(
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

        return output
