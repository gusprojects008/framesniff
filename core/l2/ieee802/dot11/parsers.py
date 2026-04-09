import struct
import binascii
import re
import socket
from logging import getLogger
from core.common.parser_utils import (unpack, bytes_for_mac, bitmap_value_for_dict, mac_vendor_resolver)
from core.common.constants.l2 import (EUI48_LENGTH)
from core.common.constants.ieee802_11 import *
from core.l2.ieee802.dot11.ies_parsers import IE_DISPATCHER
from core.l2.ieee802.llc import parse as llc_parser
from core.l3 import parsers as l3_parsers

logger = getLogger(__name__)

# Parsers that can be used in both management frames and data frames
def mac_header(frame: bytes, offset: int = 0) -> tuple[dict, int]:
    logger.debug("function mac_header parser:")

    mac_data = {}

    def _get_frame_type_subtype_name(frame_type: int, subtype: int) -> tuple[str, str]:
        type_name = FRAME_TYPES.get(frame_type, f"Unknown ({frame_type})")
        subtype_name = FRAME_SUBTYPES.get(frame_type, {}).get(subtype, f"Unknown {type_name} ({subtype})")
        return type_name, subtype_name

    try:
        fc_result, offset = unpack("<H", frame, offset)
        frame_control = fc_result["value"]

        frame_type     = (frame_control >> 2) & 0b11
        frame_subtype  = (frame_control >> 4) & 0b1111
        protected      = bool(frame_control & 0x4000)
        protocol_version = frame_control & 0b11
        to_ds          = (frame_control >> 8) & 1
        from_ds        = (frame_control >> 9) & 1
        is_qos         = frame_type == DATA and bool(frame_subtype & 0b1000)

        frame_type_name, frame_subtype_name = _get_frame_type_subtype_name(frame_type, frame_subtype)

        mac_data["fc"] = {
            "protocol_version": protocol_version,
            "type":             frame_type,
            "type_name":        frame_type_name,
            "subtype":          frame_subtype,
            "subtype_name":     frame_subtype_name,
            "tods":             to_ds,
            "fromds":           from_ds,
            "protected":        protected,
        }

        duration_result, offset = unpack("<H", frame, offset)
        mac_data["duration_id"] = duration_result["value"]

        addr1 = addr2 = addr3 = addr4 = sequence_number = None

        if frame_type == CTRL:
            if frame_subtype in (CTRL_BLOCK_ACK_REQUEST, CTRL_BLOCK_ACK, CTRL_PS_POLL,
                                  CTRL_RTS, CTRL_CF_END, CTRL_CF_END_ACK):
                unpacked_result, offset = unpack(f"<{EUI48_LENGTH}s{EUI48_LENGTH}s", frame, offset)
                addr1, addr2 = unpacked_result["value"]
            elif frame_subtype in (CTRL_CTS, CTRL_ACK):
                unpacked_result, offset = unpack(f"<{EUI48_LENGTH}s", frame, offset)
                addr1 = unpacked_result["value"]
        else:
            unpacked_result, offset = unpack(f"<{EUI48_LENGTH}s{EUI48_LENGTH}s{EUI48_LENGTH}sH", frame, offset)
            addr1, addr2, addr3, sequence_number = unpacked_result["value"]

        if to_ds and from_ds and offset + EUI48_LENGTH <= len(frame):
            addr4 = frame[offset:offset + EUI48_LENGTH]

        mac_receiver    = mac_vendor_resolver.mac_resolver(addr1)
        mac_transmitter = mac_vendor_resolver.mac_resolver(addr2)
        bssid           = mac_vendor_resolver.mac_resolver(addr3)
        mac_source = mac_destination = None

        if to_ds == 0 and from_ds == 0:
            mac_source, mac_destination = mac_transmitter, mac_receiver
        elif to_ds == 0 and from_ds == 1:
            mac_source, mac_destination = mac_vendor_resolver.mac_resolver(addr3), mac_receiver
            bssid = mac_transmitter
        elif to_ds == 1 and from_ds == 0:
            mac_source, mac_destination = mac_transmitter, mac_vendor_resolver.mac_resolver(addr3)
            bssid = mac_receiver
        elif to_ds == 1 and from_ds == 1:
            mac_source      = mac_vendor_resolver.mac_resolver(addr4) if addr4 else mac_transmitter
            mac_destination = mac_vendor_resolver.mac_resolver(addr3)
            bssid           = None

        qos_control = None
        if is_qos:
            qos_result, offset = unpack("<H", frame, offset)
            qos_control = qos_result["value"]

        mac_data.update({"ra": mac_receiver, "ta": mac_transmitter})

        if frame_type in (MGMT, DATA):
            mac_data.update({
                "sa":              mac_source,
                "da":              mac_destination,
                "bssid":           bssid,
                "sequence_number": sequence_number,
                "qos_control":     qos_control,
            })
    except Exception as e:
        logger.debug(f"MAC Header parser error: {e}")
    return mac_data, offset

def fixed_parameters(frame: bytes, offset: int) -> tuple[dict, int]:
    logger.debug(f"Parsing fixed parameters: frame: {frame} offset {offset}")
    unpacked_result, offset = unpack("<QHH", frame, offset)
    timestamp, beacon_interval, capabilities_information = unpacked_result["value"]
    capabilities_information_list = [
        "ess_capabilities", "ibss_status", "reserved1", "reserved2",
        "privacy", "short_preamble", "critical_update_flag",
        "nontransmitted_bssid_critical_update_flag", "spectrum_management",
        "qos", "short_slot_time", "automatic_power_save_delivery",
        "radio_measurement", "epd", "reserved3", "reserved4",
    ]
    return {
        "timestamp":                timestamp,
        "beacon_interval":          beacon_interval,
        "capabilities_information": bitmap_value_for_dict(capabilities_information, capabilities_information_list),
    }, offset

def tagged_parameters(frame: bytes, offset: int) -> tuple[dict, int]:
    logger.debug(f"Parsing tagged parameters: offset={offset}")

    def _insert_ie(container: dict, key: str | int, value: dict | str | int):
        if key not in container:
            container[key] = value
            return
        if not isinstance(container[key], dict) or not all(k.isdigit() for k in container[key]):
            container[key] = {"1": container[key]}
        idx = str(len(container[key]) + 1)
        container[key][idx] = value

    flen   = len(frame)
    result = {}

    while offset + MIN_IE_LEN <= flen:
        ie_result, offset = unpack("<BB", frame, offset, ie_dispatch)
        ie = ie_result["parsed"] # ie_dispatch returns the enriched dict via parser=
        tag_name = ie.get("tag_name")
        tag_number = ie.get("tag_number")
        _insert_ie(result, tag_name or tag_number, ie)

    return result, offset

# Parsers of management frame subtypes and their dispatch table
def mgmt_beacon(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    fp, offset = fixed_parameters(frame, offset)
    tp, offset = tagged_parameters(frame, offset)
    return {"fixed_parameters": fp, "tagged_parameters": tp}, offset


def mgmt_probe_response(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    return mgmt_beacon(frame, offset)


def mgmt_atim(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    aid_result, offset = unpack("<H", frame, offset)
    return {"aid": aid_result["value"] & 0x3FFF}, offset


def mgmt_disassociation(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    reason_result, offset = unpack("<H", frame, offset)
    return {"reason_code": reason_result["value"]}, offset


def mgmt_deauthentication(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    reason_result, offset = unpack("<H", frame, offset)
    return {"reason_code": reason_result["value"]}, offset


def mgmt_authentication(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    auth_alg_result,  offset = unpack("<H", frame, offset)
    auth_seq_result,  offset = unpack("<H", frame, offset)
    status_result,    offset = unpack("<H", frame, offset)
    fp, offset = fixed_parameters(frame, offset)
    tp, offset = tagged_parameters(frame, offset)
    return {
        "auth_algorithm":    auth_alg_result["value"],
        "auth_sequence":     auth_seq_result["value"],
        "status_code":       status_result["value"],
        "fixed_parameters":  fp,
        "tagged_parameters": tp,
    }, offset


def mgmt_action(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    category_result, offset = unpack("B", frame, offset)
    action_result,   offset = unpack("B", frame, offset)
    body = {
        "category": category_result["value"],
        "action":   action_result["value"],
    }
    if offset < len(frame):
        tp, offset = tagged_parameters(frame, offset)
        body["tagged_parameters"] = tp
    return body, offset

MGMT_FRAME_DISPATCH = {
    MGMT_BEACON: {
        "name": "beacon",
        "parser": mgmt_beacon
    },
    MGMT_PROBE_RESPONSE: {
        "name": "probe_response",
        "parser": mgmt_probe_response
    },
    MGMT_ATIM: {
        "name": "atim",
        "parser": mgmt_atim
    },
    MGMT_DISASSOCIATION: {
        "name": "disassociation",
        "parser": mgmt_disassociation
    },
    MGMT_DEAUTHENTICATION: {
        "name": "deauthentication",
        "parser": mgmt_deauthentication
    },
    MGMT_AUTHENTICATION: {
        "name": "authentication",
        "parser": mgmt_authentication
    },
    MGMT_ACTION: {
        "name": "action",
        "parser": mgmt_action
    }
}

# Parsers of control frame subtypes and their dispatch table
def ctrl_block_ack_request(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    bac_result, offset = unpack("<H", frame, offset)
    bas_result, offset = unpack("<H", frame, offset)
    return {
        "block_ack_control":   bac_result["value"],
        "block_ack_start_seq": bas_result["value"],
    }, offset


def ctrl_block_ack(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    bab_result, offset = unpack("<Q", frame, offset)
    return {"block_ack_bitmap": bab_result["value"]}, offset


def ctrl_ps_poll(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    aid_result, offset = unpack("<H", frame, offset)
    return {"aid": aid_result["value"] & 0x3FFF}, offset


def ctrl_ack(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    return {}, offset


def ctrl_cf_end(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    return {}, offset


def ctrl_cf_end_ack(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    return {}, offset

CTRL_FRAME_DISPATCH = {
    CTRL_BLOCK_ACK_REQUEST: {
        "name": "block_ack_request",
        "parser": ctrl_block_ack_request
    },
    CTRL_BLOCK_ACK: {
        "name": "block_ack",
        "parser": ctrl_block_ack
    },
    CTRL_PS_POLL: {
        "name": "ps_poll",
        "parser": ctrl_ps_poll
    },
    CTRL_ACK: {
        "name": "ack",
        "parser": ctrl_ack
    },
    CTRL_CF_END: {
        "name": "cf_end",
        "parser": ctrl_cf_end
    },
    CTRL_CF_END_ACK: {
        "name": "cf_end_ack",
        "parser": ctrl_cf_end_ack
    }
}

# Parsers payloads LLC of the IEEE 80211 standard
def eapol(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    def _parse_key_data(frame: bytes, offset: int) -> tuple[dict, int]:
        return tagged_parameters(frame, offset)

    result = {}
    try:
        header_result, offset = unpack("!BBH", frame, offset)
        auth_ver, eapol_type, length = header_result["value"]
        result.update({
            "authentication_version": auth_ver,
            "type":                   eapol_type,
            "header_length":          length,
        })

        keyfields_result, offset = unpack("!BHH", frame, offset)
        desc_type, key_info, key_len = keyfields_result["value"]

        key_descriptor_version = key_info & 0x0007
        key_type_bit           = (key_info >> 3)  & 0x01
        key_index              = (key_info >> 4)  & 0x03
        install_bit            = (key_info >> 6)  & 0x01
        ack_bit                = (key_info >> 7)  & 0x01
        mic_bit                = (key_info >> 8)  & 0x01
        secure_bit             = (key_info >> 9)  & 0x01
        error_bit              = (key_info >> 10) & 0x01
        request_bit            = (key_info >> 11) & 0x01
        encrypted_key_data     = (key_info >> 12) & 0x01
        smk_message            = (key_info >> 13) & 0x01

        version_map = {
            0: "Reserved(0)",
            1: "HMAC-MD5_ARC4_WPA1",
            2: "HMAC-SHA1-128_AES_WPA2_RSN",
            3: "AES-128-CMAC_AES-128-GCMP_WPA3",
            **{i: f"Reserved({i})" for i in range(4, 8)},
        }

        result.update({
            "key_descriptor_type": desc_type,
            "key_information": {
                "key_descriptor_version": {
                    "value":       key_descriptor_version,
                    "description": version_map.get(key_descriptor_version, "Unknown"),
                },
                "key_type": {
                    "value":       key_type_bit,
                    "description": "group_smk" if key_type_bit else "pairwise",
                },
                "key_index":           key_index,
                "install":             bool(install_bit),
                "key_ack":             bool(ack_bit),
                "key_mic":             bool(mic_bit),
                "secure":              bool(secure_bit),
                "error":               bool(error_bit),
                "request":             bool(request_bit),
                "encrypted_key_data":  bool(encrypted_key_data),
                "smk_message":         bool(smk_message),
            },
            "key_length": key_len,
        })

        fmt = (
            f"!{EAPOL_REPLAY_COUNTER_LENGTH}s{EAPOL_NONCE_LENGTH}s"
            f"{EAPOL_KEY_IV_LENGTH}s{EAPOL_KEY_RSC_LENGTH}s"
            f"{EAPOL_KEY_ID_LENGTH}s{EAPOL_KEY_MIC_LENGTH}s"
            f"{EAPOL_KEY_DATA_LENGTH_FIELD}"
        )
        bulk_result, offset = unpack(fmt, frame, offset)
        replay, nonce, iv, rsc, key_id, mic, data_len = bulk_result["value"]

        result.update({
            "replay_counter":    replay,
            "key_nonce":         nonce.hex(),
            "key_iv":            iv.hex(),
            "key_rsc":           rsc.hex(),
            "key_id":            key_id.hex(),
            "key_mic":           mic,
            "key_data_length":   data_len,
        })

        if data_len > 0 and offset + data_len <= len(frame):
            key_data_parsed, offset = _parse_key_data(frame, offset)
            result["key_data"] = key_data_parsed

    except Exception as e:
        logger.debug(f"EAPOL Parser error: {e}")

    return result, offset


def mgmt_frame(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    subtype = kwargs["subtype"]
    return run_dispatch(
        frame,
        offset
        MGMT_FRAME_DISPATCH,
        subtype,
    )

def ctrl_frame(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    subtype = kwargs["subtype"]
    return run_dispatch(
        frame,
        offset
        CTRL_FRAME_DISPATCH,
        subtype,
    )

def data_frame(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
    body = {}
    llc, offset = llc_parser.parse(frame, offset)
    body["llc"] = llc
    return body, offset


BODY_DISPATCH = {
    MGMT: mgmt_frame,
    CTRL: ctrl_frame,
    DATA: data_frame,
}

def body_dispatch(
    frame: bytes,
    frame_type: int,
    frame_subtype: int,
    protected: bool,
    offset: int = 0,
) -> tuple[dict, int]:

    body = {}

    if protected:
        logger.debug(f"Protected frame")
        remaining = len(frame) - offset
        return unpack(f"{remaining}s", frame, offset)

    def _unknown_type_fallback(frame: bytes, offset: int, **kwargs) -> tuple[dict, int]:
        logger.debug(f"Unknown frame type: {kwargs.get('frame_type')}")
        remaining = len(frame) - offset
        return unpack(f"{remaining}s", frame, offset)

    try:
        body, offset = run_dispatch(
            frame,
            offset,
            BODY_DISPATCH,
            frame_type,
            fallback=_unknown_type_fallback,
            frame_type=frame_type,
            subtype=frame_subtype,
            protected=protected,
        )
    except Exception as e:
        logger.debug(f"body_dispatch error: {e}")

    return body, offset
