from logging import getLogger
from core.common.parser_utils import (unpack, bytes_for_mac) 
from core.l2.ieee802.dot11 import parsers as dot11_parsers 
from core.l3 import parsers as l3_parsers

logger = getLogger(__name__)

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

def parse(frame: bytes, offset: int):
    def _llc_payload_parse_fallback(payload: bytes, offset: int):
        return unpack(f"{flen - offset}s", frame, offset)

    logger.debug(f"LLC parser: offset={offset}")

    body = {}
    start = offset
    flen = len(frame)

    try:
        result, offset = unpack("!BBB3sH", frame, offset)
        
        (dsap, ssap, control, org_code, llc_type) = result.get("value")

        org_code = bytes_for_mac(org_code)

        body.update({
            "dsap": dsap,
            "ssap": ssap,
            "control_field": control,
            "organization_code": org_code,
            "type": llc_type,
        })

        payload_start = offset

        handler = LLC_PAYLOAD_DISPATCH.get(llc_type, {})

        name = handler.get("name", llc_type)
        parser = handler.get("parser")

        body[name] = {}

        if parser:
            content, offset = parser(frame, offset)
            body[name].update(content)
        else:
            offset = flen

    except Exception as e:
        logger.debug(f"LLC parser error: {e}")

    return body, offset
