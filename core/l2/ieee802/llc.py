from logging import getLogger
from core.common.parser_utils import (unpack, bytes_for_mac) 

logger = getLogger(__name__)

def parse(frame: bytes, offset: int):
    start_offset = offset
    logger.debug(f"LLC parser: {frame, offset}")
    result = {}
    (unpacked), offset = unpack("!BBB3sH", frame, offset)
    logger.debug(f"{unpacked}")
    dsap, ssap, control, org_code, llc_type = unpacked
    result.update({
        "dsap": dsap,
        "ssap": ssap,
        "control_field": control,
        "organization_code": bytes_for_mac(org_code),
        "type": llc_type
        "raw": frame[start_offset:offset].hex()
        "start_offset": start_offset
        "end_offset": offset
    })
    return result, offset


LLC_PAYLOAD_DISPATCH = {
    LLC_EAPOL: {
        "name": "eapol",
        "parser": dot11_parsers.eapol
    },
    LLC_IPV4: {
        "name": "ip",
        "parser": l3_parsers.ip
    },
    LLC_ARP: {
        "name": "arp",
        "parser": l3_parsers.arp
    },
    LLC_IPV6: {
        "name": "ipv6",
        "parser": l3_parsers.ipv6
    },
    LLC_MESH_CTRL: {
        "name": "mesh_ctrl",
        "parser": None
    },
    LLC_TDLS: {
        "name": "tdls",
        "parser": None
    },
    LLC_WAPI: {
        "name": "wapi",
        "parser": None
    },
    LLC_FAST_BSS_TRANSITION: {
        "name": "fast_bss_transition",
        "parser": None
    },
    LLC_DLS: {
        "name": "dls",
        "parser": None
    },
    LLC_RAS: {
        "name": "robust_av_streaming",
        "parser": None
    },
    LLC_WMM: {
        "name": "wmm",
        "parser": None
    },
    LLC_QOS_NULL: {
        "name": "qos_null",
        "parser": None
    }
}
