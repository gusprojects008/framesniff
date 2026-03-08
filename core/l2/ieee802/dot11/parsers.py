import struct
import binascii
import re
import socket
from logging import getLogger
from core.common.parser_utils import (unpack, bytes_for_mac, bitmap_value_for_dict)
from core.common.constants.l2 import (EUI48_LENGTH)
from core.common.constants.ieee802_11 import *
from core.l2.ieee802.dot11.ies_parsers import IE_DISPATCHER
from core.l3 import parsers as l3_parsers

logger = getLogger(__name__)

def mac_header(frame: bytes, mac_vendor_resolver: object, offset: int = 0) -> tuple(dict, int):
    logger.debug("function mac_header parser:")

    mac_data = {}

    def _get_frame_type_subtype_name(frame_type: int, subtype: int) -> tuple(str, str):
        type_name = FRAME_TYPES.get(frame_type, f"Unknown ({frame_type})")
        subtype_name = FRAME_SUBTYPES.get(frame_type, {}).get(subtype, f"Unknown {type_name} ({subtype})")
        return type_name, subtype_name

    try:
        frame_control, offset = unpack("<H", frame, offset)
        frame_type = (frame_control >> 2) & 0b11
        frame_subtype = (frame_control >> 4) & 0b1111
        frame_type_name, frame_subtype_name = _get_frame_type_subtype_name(frame_type, frame_subtype)
        protected = bool(frame_control & 0x4000)
        protocol_version = frame_control & 0b11
        to_ds = (frame_control >> 8) & 1
        from_ds = (frame_control >> 9) & 1
        is_qos = (frame_type == DATA and (frame_subtype & 0b1000))
        qos_control = None

        mac_data.update({
            "fc": {
                "protocol_version": protocol_version,
                "type": frame_type,
                "type_name": frame_type_name,
                "subtype": frame_subtype,
                "subtype_name": frame_subtype_name,
                "tods": to_ds,
                "fromds": from_ds,
                "protected": protected
        }})

        fmt = ""

        duration_id, offset = unpack("<H", frame, offset)

        addr1, addr2, addr3, addr4, sequence_number = None, None, None, None, None, None

        if frame_type == CTRL:
            if frame_subtype in (CTRL_BLOCK_ACK_REQUEST, CTRL_BLOCK_ACK, CTRL_PS_POLL, CTRL_RTS, CTRL_CF_END, CTRL_CF_END_ACK):
                fmt = f"<{EUI48_LENGTH}s{EUI48_LENGTH}s"  # FC, Duration, RA, TA
                unpacked, offset = unpack(fmt, frame, offset)
                addr1, addr2 = unpacked
            elif frame_subtype in (CTRL_CTS, CTRL_ACK):
                fmt = f"<{EUI48_LENGTH}s"  # FC, Duration, RA
                unpacked, offset = unpack(fmt, frame, offset)
                addr1 = unpacked
        else: # Data and Management
            fmt = f"<{EUI48_LENGTH}s{EUI48_LENGTH}s{EUI48_LENGTH}sH"
            unpacked, offset = unpack(fmt, frame, offset)
            addr1, addr2, addr3, sequence_number = unpacked

        if to_ds and from_ds and offset + EUI48_LENGTH <= len(frame):
            addr4 = frame[offset:offset+EUI48_LENGTH]

        mac_receiver = mac_vendor_resolver.mac_resolver(addr1)
        mac_transmitter = mac_vendor_resolver.mac_resolver(addr2)
        bssid = mac_vendor_resolver.mac_resolver(addr3)
        mac_source, mac_destination = None, None

        if to_ds == 0 and from_ds == 0:
            mac_source, mac_destination = mac_transmitter, mac_receiver
        elif to_ds == 0 and from_ds == 1:
            mac_source, mac_destination = mac_vendor_resolver.mac_resolver(addr3), mac_receiver
            bssid = mac_transmitter
        elif to_ds == 1 and from_ds == 0:
            mac_source, mac_destination = mac_transmitter, mac_vendor_resolver.mac_resolver(addr3)
            bssid = mac_receiver
        elif to_ds == 1 and from_ds == 1:
            mac_source, mac_destination = mac_vendor_resolver.mac_resolver(addr4) if addr4 else mac_transmitter, mac_vendor_resolver.mac_resolver(addr3)
            bssid = None

        if is_qos:
            qos_control, offset = unpack("<H", frame, offset)

        mac_data.update({
            "ra": mac_receiver,
            "ta": mac_transmitter
        })

        if frame_type in [MGMT, DATA]:
            mac_data.update({
                "sa": mac_source,
                "da": mac_destination,
                "bssid": bssid,
                "sequence_number": sequence_number,
                "qos_control": qos_control
            })

    except Exception as e:
        logger.debug(f"MAC Header parser error: {e}")

    return mac_data, offset

def fixed_parameters(frame: bytes, offset: int) -> tuple(dict, int):
    logger.debug(f"Parsing fixed parameters: frame: {frame} offset {offset}")
    fixed_parameters = {}
    unpacked, offset = unpack("<QHH", frame, offset)
    timestamp, beacon_interval, capabilities_information = unpacked
    fixed_parameters['timestamp'] = timestamp
    fixed_parameters['beacon_interval'] = beacon_interval
    capabilities_information_list = ["ess_capabilities", "ibss_status", "reserved1", "reserved2", "privacy", "short_preamble", "critical_update_flag", "nontransmitted_bssid_critical_update flag", "spectrum_management", "qos", "short_slot_time", "automatic_power_save_delivery", "radio_measurement", "epd", "reserved3", "reserved4"]
    fixed_parameters['capabilities_information'] = bitmap_value_for_dict(capabilities_information, capabilities_information_list)
    return fixed_parameters, offset

def tagged_parameters(frame: bytes, offset: int) -> tuple(dict, int):
    logger.debug(f"Parsing tagged parameters: offset={offset}")
    tagged_parameters = {}
    ie_min_len = 2
    flen = len(frame)

    try:
        while offset + ie_min_len <= flen:
            (tag_number, tag_length), offset = unpack("<BB", frame, offset)

            if offset + tag_length > flen:
                logger.debug("Truncated IE detected")
                break

            data, offset = unpack(f"{tag_length}s", frame, offset)

            ie_data = {
                "tag_number": tag_number,
                "tag_length": tag_length,
                "raw": data.hex()
            }

            entry = IE_DISPATCHER.get(tag_number)

            if entry:
                name = entry["name"]
                parser = entry.get("parser")
                
                if parser:
                    try:
                        ie_data["parsed"] = parser(data, tag_length)
                    except Exception as e:
                        logger.debug(f"IE parser error ({name}): {e}")
                
                if name in tagged_parameters:
                    if not isinstance(tagged_parameters[name], dict) or not all(k.isdigit() for k in tagged_parameters[name].keys()):
                        first = tagged_parameters[name]
                        tagged_parameters[name] = {"1": first}
                    next_idx = str(len(tagged_parameters[name]) + 1)
                    tagged_parameters[name][next_idx] = ie_data
                else:
                    tagged_parameters[name] = ie_data
            else:
                key = str(tag_number)
                if key in tagged_parameters:
                    if not isinstance(tagged_parameters[key], dict) or not all(k.isdigit() for k in tagged_parameters[key].keys()):
                        first = tagged_parameters[key]
                        tagged_parameters[key] = {"1": first}
                    next_idx = str(len(tagged_parameters[key]) + 1)
                    tagged_parameters[key][next_idx] = ie_data
                else:
                    tagged_parameters[key] = ie_data
    except Exception as e:
        logger.debug(f"Tagged parameters parser error: {e}")

    return tagged_parameters, offset

def mgmt_beacon(frame: bytes, offset: int):
    body = {}
    fixed_parameters, offset = fixed_parameters(frame, offset)
    body["fixed_parameters"] = fixed_parameters

    tagged_parameters, offset = tagged_parameters(frame, offset)
    body["tagged_parameters"] = tagged_parameters

    return body, offset


def mgmt_probe_response(frame: bytes, offset: int) -> tuple(dict, int):
    return mgmt_beacon(frame, offset)


def mgmt_atim(frame: bytes, offset: int) -> tuple(dict, int):
    body = {}
    aid_raw, offset = unpack("<H", frame, offset)
    body["aid"] = aid_raw & 0x3FFF
    return body, offset


def mgmt_disassociation(frame: bytes, offset: int) -> tuple(dict, int):
    body = {}
    body["reason_code"], offset = unpack("<H", frame, offset)
    return body, offset


def mgmt_deauthentication(frame: bytes, offset: int) -> tuple(dict, int):
    body = {}
    body["reason_code"], offset = unpack("<H", frame, offset)
    return body, offset


def mgmt_authentication(frame: bytes, offset: int) -> tuple(dict, int):
    body = {}

    body["auth_algorithm"], offset = unpack("<H", frame, offset)
    body["auth_sequence"], offset = unpack("<H", frame, offset)
    body["status_code"], offset = unpack("<H", frame, offset)

    fixed_parameters, offset = fixed_parameters(frame, offset)
    body["fixed_parameters"] = fixed_parameters

    tagged_parameters, offset = tagged_parameters(frame, offset)
    body["tagged_parameters"] = tagged_parameters

    return body, offset


def mgmt_action(frame: bytes, offset: int) -> tuple(dict, int):
    body = {}

    body["category"], offset = unpack("B", frame, offset)
    body["action"], offset = unpack("B", frame, offset)

    if offset < len(frame):
        tagged_parameters, offset = tagged_parameters(frame, offset)
        body["tagged_parameters"] = tagged_parameters

    return body, offset

def eapol(frame: bytes, offset: int) -> tuple(dict, int):
    def _parse_key_data(key_data: bytes, offset: int) -> dict:
        result = tagged_parameters(key_data, offset)
        return result, offset
    result = {}
    try:
        (auth_ver, eapol_type, length), offset = unpack("!BBH", frame, offset)

        result.update({
            "authentication_version": auth_ver,
            "type": eapol_type,
            "header_length": length,
        })

        (desc_type, key_info, key_len), offset = unpack("!BHH", frame, offset)

        key_descriptor_version = key_info & 0x0007
        key_type_bit = (key_info >> 3) & 0x01
        key_index = (key_info >> 4) & 0x03
        install_bit = (key_info >> 6) & 0x01
        wack_bit = (key_info >> 7) & 0x01
        mic_bit = (key_info >> 8) & 0x01
        secure_bit = (key_info >> 9) & 0x01
        error_bit = (key_info >> 10) & 0x01
        request_bit = (key_info >> 11) & 0x01
        encrypted_key_data = (key_info >> 12) & 0x01
        smk_message = (key_info >> 13) & 0x01

        version_map = {
            0: "Reserved(0)",
            1: "HMAC-MD5_ARC4_WPA1",
            2: "HMAC-SHA1-128_AES_WPA2_RSN",
            3: "AES-128-CMAC_AES-128-GCMP_WPA3",
            4: "Reserved(4)", 
            5: "Reserved(5)",
            6: "Reserved(6)",
            7: "Reserved(7)"
        }
        
        result.update({
            "key_descriptor_type": desc_type,
            "key_information": {
                "key_descriptor_version": {
                    "value": key_descriptor_version,
                    "description": version_map.get(key_descriptor_version, "Unknown")
                },
                "key_type": {
                    "value": key_type_bit,
                    "description": "group_smk" if key_type_bit else "pairwise"
                },
                "key_index": key_index,
                "install": bool(install_bit),
                "key_ack": bool(ack_bit),
                "key_mic": bool(mic_bit),
                "secure": bool(secure_bit),
                "error": bool(error_bit),
                "request": bool(request_bit),
                "encrypted_key_data": bool(encrypted_key_data),
                "smk_message": bool(smk_message),
            },
            "key_length": key_len,
        })

        unpacked, offset = unpack(f"!{EAPOL_REPLAY_COUNTER_LENGTH}s{EAPOL_NONCE_LENGTH}s{EAPOL_KEY_IV_LENGTH}s{EAPOL_KEY_RSC_LENGTH}s{EAPOL_KEY_ID_LENGTH}s{EAPOL_KEY_MIC_LENGTH}s{EAPOL_KEY_DATA_LENGTH_FIELD}", frame, offset)
        replay, nonce, iv, rsc, key_id, mic, data_len = unpacked

        nonce_hex = nonce.hex()
        iv_hex = iv.hex()
        rsc_hex = rsc.hex()
        key_id_hex = key_id.hex()
        mic_hex = mic.hex()

        result.update({
            "replay_counter": replay,
            "key_nonce": nonce_hex,
            "key_iv": iv_hex,
            "key_rsc": rsc_hex,
            "key_id": key_id_hex,
            "key_mic": mic,
            "key_data_length": data_len
        })

        if data_len > 0 and offset + data_len <= len(frame):
            key_data_parsed, offset = _parse_key_data(key_data, offset)
            key_data_hex = key_data.hex()
            result["key_data"] = key_data_parsed

    except Exception as e:
        logger.debug(f"EAPOL Parser error: {e}")

    return result, offset

def ctrl_block_ack_request(frame: bytes, offset: int):
    body = {}
    block_ack_control, offset = unpack("<H", frame, offset)
    block_ack_start_seq, offset = unpack("<H", frame, offset)
    body["block_ack_control"] = block_ack_control
    body["block_ack_start_seq"] = block_ack_start_seq
    return body, offset


def ctrl_block_ack(frame: bytes, offset: int):
    body = {}
    block_ack_bitmap, offset = unpack("<Q", frame, offset)
    body["block_ack_bitmap"] = block_ack_bitmap
    return body, offset


def ctrl_ps_poll(frame: bytes, offset: int):
    body = {}
    aid, offset = unpack("<H", frame, offset)
    body["aid"] = aid & 0x3FFF
    return body, offset


def ctrl_ack(frame: bytes, offset: int):
    return {}, offset


def ctrl_cf_end(frame: bytes, offset: int):
    return {}, offset


def ctrl_cf_end_ack(frame: bytes, offset: int):
    return {}, offset

FRAME_DISPATCH = {
    MGMT: {
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
    },

    CTRL: {
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
}

def dispatch(frame: bytes, type: int, subtype: int, protected: bool, offset: int = 0) -> dict:
    body = {}
    flen = len(frame)

    payload = frame[offset:flen].hex()

    if protected:
        body["payload"] = payload
        return body

    try:

        type_table = FRAME_DISPATCH.get(type)

        if not type_table:
            body["payload"] = payload
            return body

        handler = type_table.get(subtype)

        if not handler:
            body["payload"] = payload
            return body

        parsed, offset = run_dispatch(frame, offset, payload, handler)
        body.update(parsed)

    except Exception as e:
        logger.debug(f"Dispatch parser error: {e}")
        body["payload"] = payload

    return body
