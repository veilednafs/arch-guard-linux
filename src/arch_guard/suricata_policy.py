from __future__ import annotations


STREAM_NOISE_SIDS = {
    2210044,
    2210054,
    2210063,
}

WARP_ENGINE_NOISE_SIDS = {
    2210059,
    2210063,
}

WARP_CHECKSUM_SID = 2200075


def apply_suricata_policy(
    event: dict,
) -> dict:

    result = dict(event)

    severity = str(
        result.get(
            "severity",
            "INFO",
        )
    ).upper()

    signature = str(
        result.get(
            "signature"
        )
        or ""
    )

    sid = result.get(
        "signature_id"
    )

    profile = str(
        result.get(
            "sensor_profile",
            "default",
        )
    ).lower()

    direction = str(
        result.get(
            "direction",
            "TRANSIT_OR_UNKNOWN",
        )
    )

    suppressed = False
    reason = None

    #
    # 1. ET INFO
    #
    if signature.startswith(
        "ET INFO "
    ):
        suppressed = True
        reason = "et_info"

    #
    # 2. Suricata stream motorunun,
    #    bizim başlattığımız veya geri dönen
    #    trafik üzerindeki diagnostikleri.
    #
    elif (
        direction in {
            "SELF_OUTBOUND",
            "RETURN_TRAFFIC",
        }
        and sid in STREAM_NOISE_SIDS
    ):
        suppressed = True

        if direction == "SELF_OUTBOUND":
            reason = (
                "self_outbound_stream_noise"
            )
        else:
            reason = (
                "return_traffic_stream_noise"
            )

    #
    # 3. WARP sanal arayüzündeki bilinen
    #    Suricata engine diagnostikleri.
    #
    elif (
        profile == "warp"
        and sid in WARP_ENGINE_NOISE_SIDS
    ):
        suppressed = True
        reason = "warp_engine_noise"

    #
    # 4. WARP checksum olayı ancak gerçekten
    #    warp-svc akışı olduğu ayrıca
    #    doğrulanmışsa susturulur.
    #
    elif (
        sid == WARP_CHECKSUM_SID
        and result.get(
            "warp_transport_confirmed"
        ) is True
    ):
        suppressed = True
        reason = (
            "warp_transport_checksum_noise"
        )

    #
    # 5. Tailscale Go HTTP Client yalnızca
    #    outbound ve socket sahibi tailscaled
    #    olarak doğrulanmışsa gürültüdür.
    #
    elif (
        direction == "SELF_OUTBOUND"
        and signature.startswith(
            "ET USER_AGENTS Go HTTP Client"
        )
        and result.get(
            "tailscale_process_confirmed"
        ) is True
    ):
        suppressed = True
        reason = "tailscale_go_http_client"

    #
    # 6. Tor kuralı.
    #
    # Tor imzasını tek başına susturmuyoruz.
    # Yalnız bizim başlattığımız veya canlı
    # olarak geri dönüş olduğu kanıtlanan
    # akışlarda log-only yapıyoruz.
    #
    elif (
        signature.startswith(
            "ET TOR "
        )
        and direction in {
            "SELF_OUTBOUND",
            "RETURN_TRAFFIC",
        }
    ):
        suppressed = True
        reason = (
            "tor_locally_initiated_or_return"
        )

    notify = (
        severity != "INFO"
        and not suppressed
    )

    #
    # Legacy bug düzeltmesi:
    #
    # Eski adapter notify'ı bastırsa bile
    # HIGH/CRITICAL için snapshot alıyordu.
    #
    # Yeni sürümde bastırılmış olay
    # incident snapshot üretmez.
    #
    snapshot = (
        severity in {
            "HIGH",
            "CRITICAL",
        }
        and not suppressed
    )

    result.update(
        {
            "notify":
                notify,

            "snapshot":
                snapshot,

            "suppressed":
                suppressed,

            "suppression_reason":
                reason,
        }
    )

    return result
