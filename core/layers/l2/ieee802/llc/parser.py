from logging import getLogger
from core.common.parser_utils import (unpack, bytes_for_mac) 
from core.layers.l2.ieee802.dot11.data import (eapol)
from core.layers.l3.parsers import (ip, arp, ipv6)

logger = getLogger(__name__)

LLC_PAYLOAD_DISPATCH = {
    LLC_EAPOL: {
        "name": "eapol",
        "description": "EAP over LAN",
        "parser": eapol
    },
    LLC_IPV4: {
        "name": "ip",
        "description": "IPv4",
        "parser": ip
    },
    LLC_ARP: {
        "name": "arp",
        "description": "Address Resolution Protocol",
        "parser": arp
    },
    LLC_IPV6: {
        "name": "ipv6",
        "description": "IPv6",
        "parser": ipv6
    },
    LLC_MESH_CTRL: {
        "name": "mesh_ctrl",
        "description": "Mesh Control",
        "parser": None
    },
    LLC_TDLS: {
        "name": "tdls",
        "description": "Tunneled Direct Link Setup",
        "parser": None
    },
    LLC_WAPI: {
        "name": "wapi",
        "description": "WLAN Authentication and Privacy Infrastructure",
        "parser": None
    },
    LLC_FAST_BSS_TRANSITION: {
        "name": "fast_bss_transition",
        "description": "Fast BSS Transition",
        "parser": None
    },
    LLC_DLS: {
        "name": "dls",
        "description": "Direct Link Setup",
        "parser": None
    },
    LLC_RAS: {
        "name": "robust_av_streaming",
        "description": "Robust Audio Video Streaming",
        "parser": None
    },
    LLC_WMM: {
        "name": "wmm",
        "description": "Wi-Fi Multimedia",
        "parser": None
    },
    LLC_QOS_NULL: {
        "name": "qos_null",
        "description": "QoS Null",
        "parser": None
    }
}

def parser(**kwargs) -> dict:
    logger.debug(f"LLC parse")

    def _parser(value: tuple, **kwargs) -> dict:
        dsap, ssap, ctrl, org_raw, proto_type = value
        
        org_code = bytes_for_mac(org_raw)
        
        entry = LLC_PAYLOAD_DISPATCH.get(proto_type, {})
        proto_name = entry.get("name", "unknown")
        proto_desc = entry.get("description", "Unknown Protocol")

        payload = run_dispatch(
            dispatch_table=LLC_PAYLOAD_DISPATCH,
            dispatch_id=proto_type
        )

        result = {
            "dsap": dsap,
            "ssap": ssap,
            "control_field": ctrl,
            "organization_code": org_code,
            "protocol_type": proto_type,
            "name": proto_name,
            "description": proto_desc,
            "payload": payload
        }
        
        return result

    return unpack("!BBB3sH", parser=_parser)
