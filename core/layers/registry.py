import dpkt
from core.layers.l2.ieee802.dot11.parse import parse as dot11_parser

PROTOCOL_MAP = {
    "DLT_IEEE802_11_RADIO": {
        "dlt_value": dpkt.pcap.DLT_IEEE802_11_RADIO,
        "parser": dot11_parser
    },
    "DLT_EN10MB": {
        "dlt_value": dpkt.pcap.DLT_EN10MB,
        "parser": None,
    },
    "DLT_BLUETOOTH_HCI_H4": {
        "dlt_value": dpkt.pcap.DLT_BLUETOOTH_HCI_H4,
        "parser": None,
    },
}

def get_parser(dlt_name):
    config = PROTOCOL_MAP.get(dlt_name)
    if not config or not config["parser"]:
        raise ValueError(f"Parser not available or not implemented for: {dlt_name}")
    return config["parser"]

def get_dlt_value(dlt_name):
    config = PROTOCOL_MAP.get(dlt_name)
    if not config:
        raise ValueError(f"Unknown DLT: {dlt_name}")
    return config["dlt_value"]

def list_supported_dlts():
    return [k for k, v in PROTOCOL_MAP.items() if v["parser"] is not None]
