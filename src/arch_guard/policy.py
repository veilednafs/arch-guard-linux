from __future__ import annotations


def apply_policy(
    event: dict,
) -> dict:
    """
    SSH ve nft/network olaylarının kullanıcı
    bildirimi ve incident snapshot politikasını
    uygular.

    Suricata kendi özel policy katmanını kullanır.
    """

    result = dict(event)

    event_type = str(
        result.get("event") or ""
    )

    severity = str(
        result.get(
            "severity",
            "INFO",
        )
    ).upper()

    notify = False
    snapshot = False

    #
    # Başarılı SSH erişimi:
    # kullanıcı bilgilendirilir fakat incident değildir.
    #
    if event_type == "ssh_auth_success":
        notify = True

    #
    # Brute-force:
    # HIGH -> popup
    # CRITICAL -> popup + incident snapshot
    #
    elif event_type == "ssh_account_locked":
        notify = True
        snapshot = True

    elif event_type == "ssh_bruteforce":
        notify = severity in {
            "HIGH",
            "CRITICAL",
        }

        snapshot = (
            severity == "CRITICAL"
        )

    #
    # Başarısız denemelerden sonra başarılı login:
    # HIGH/CRITICAL kullanıcıya gösterilir.
    # Yalnız CRITICAL incident snapshot üretir.
    #
    elif event_type == "ssh_success_after_failures":
        notify = severity in {
            "HIGH",
            "CRITICAL",
        }

        snapshot = (
            severity == "CRITICAL"
        )

    #
    # Port scan:
    # correlator bunu CRITICAL üretir.
    #
    elif event_type == "tailscale_port_scan":
        # Legacy sensör HIGH seviyede bildiriyordu.
        # Snapshot yalnız CRITICAL olaylara ayrılmıştır.
        notify = True
        snapshot = False

    elif event_type == "network_port_scan":
        notify = severity in {
            "HIGH",
            "CRITICAL",
        }

        snapshot = (
            severity == "CRITICAL"
        )

    #
    # network_probe ham gözlemdir.
    # ssh failure / session gibi olaylar log-only kalır.
    #

    result["notify"] = notify
    result["snapshot"] = snapshot

    return result
