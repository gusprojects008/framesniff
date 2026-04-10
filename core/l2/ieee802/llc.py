from logging import getLogger
from core.common.parser_utils import (unpack, bytes_for_mac) 
from core.l2.ieee802.dot11.parsers import (eapol)
from core.l3.parsers import (ip, arp, ipv6)

logger = getLogger(__name__)

LLC_PAYLOAD_DISPATCH: dict[int, tuple[str, callable | None]] = {
    LLC_EAPOL: ("eapol", eapol),
    LLC_IPV4: ("ip", ip),
    LLC_ARP: ("arp", arp),
    LLC_IPV6:("ipv6", ipv6),
    LLC_MESH_CTRL: ("mesh_ctrl", None),
    LLC_TDLS: ("tdls", None),
    LLC_WAPI: ("wapi", None),
    LLC_FAST_BSS_TRANSITION: ("fast_bss_transition", None),
    LLC_DLS: ("dls", None),
    LLC_RAS: ("robust_av_streaming", None),
    LLC_WMM: ("wmm", None),
    LLC_QOS_NULL: ("qos_null", None),
}

def parse(frame: bytes, offset: int) -> tuple[dict, int]:
    logger.debug(f"LLC parser: offset={offset}")
    body  = {}
    start = offset
    try:
        result, offset = unpack("!BBB3sH", frame, offset)
        dsap, ssap, control, org_code, llc_type = result["value"]
        org_code = bytes_for_mac(org_code)
        body.update({
            "dsap": dsap,
            "ssap": ssap,
            "control_field": control,
            "organization_code": org_code,
            "type": llc_type,
        })
        payload, offset = run_dispatch(
            frame, offset, LLC_PAYLOAD_DISPATCH, llc_type
        )
        body.update(payload)
    except Exception as e:
        logger.debug(f"LLC parser error: {e}")
    body.update(add_metadata(frame, start, offset))
    return body, offset
