import struct
import binascii
import re
import socket
from logging import getLogger
from core.common.parser_utils import (unpack, bytes_for_mac, bitmap_value_for_dict)
from core.common.constants.l2 import (EUI48_LENGTH)
from core.common.constants.ieee802_11 import *
from core.l2.ieee802.dot11.ies_parsers import IE_DISPATCHER

logger = getLogger(__name__)

def mac_header(frame: bytes, mac_vendor_resolver: object, offset: int = 0) -> (dict, int):
    logger.debug("function mac_header parser:")
    def _get_frame_type_subtype_name(frame_type: int, subtype: int):
        type_name = FRAME_TYPES.get(frame_type, f"Unknown ({frame_type})")
        subtype_name = FRAME_SUBTYPES.get(frame_type, {}).get(subtype, f"Unknown {type_name} ({subtype})")
        return type_name, subtype_name

    mac_data = {}

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

        duration_id, addr1, addr2, addr3, sequence_number = None, None, None, None, None

        if frame_type == CTRL:
            if frame_subtype in (CTRL_BLOCK_ACK_REQUEST, CTRL_BLOCK_ACK, CTRL_PS_POLL, CTRL_RTS, CTRL_CF_END, CTRL_CF_END_ACK):
                fmt = f"<H{EUI48_LENGTH}s{EUI48_LENGTH}s"  # FC, Duration, RA, TA
                unpacked, offset = unpack(fmt, frame, offset)
                duration_id, addr1, addr2 = unpacked
            elif frame_subtype in (CTRL_CTS, CTRL_ACK):
                fmt = f"<H{EUI48_LENGTH}s"  # FC, Duration, RA
                unpacked, offset = unpack(fmt, frame, offset)
                duration_id, addr1 = unpacked
            else:
                fmt = "<H"  # fallback minimal
                duration_id, offset = unpack(fmt, frame, offset)
        else: # Data and Management
            fmt = f"<H{EUI48_LENGTH}s{EUI48_LENGTH}s{EUI48_LENGTH}sH"
            unpacked, offset = unpack(fmt, frame, offset)
            duration_id, addr1, addr2, addr3, sequence_number = unpacked

        addr4 = None
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
            "mac_receiver": mac_receiver,
            "mac_transmitter": mac_transmitter
        })

        if frame_type in [MGMT, DATA]:
            mac_data.update({
                "mac_src": mac_source,
                "mac_dst": mac_destination,
                "bssid": bssid,
                "sequence_number": sequence_number,
                "qos_control": qos_control
            })

        return mac_data, offset

    except struct.error as e:
        logger.debug(f"MAC Header parser error: {e}")
        return mac_data, offset

def fixed_parameters(frame: bytes, offset: int) -> (dict, int):
    logger.debug(f"Parsing fixed parameters: frame: {frame} offset {offset}")
    fixed_parameters = {}
    unpacked, offset = unpack("<QHH", frame, offset)
    timestamp, beacon_interval, capabilities_information = unpacked
    fixed_parameters['timestamp'] = timestamp
    fixed_parameters['beacon_interval'] = beacon_interval
    capabilities_information_list = ["ess capabilities", "ibss status", "reserved1", "reserved2", "privacy", "short preamble", "critical update flag", "nontransmitted bssid critical update flag", "spectrum management", "qos", "short slot time", "automatic power save delivery", "radio measurement", "epd", "reserved3", "reserved4"]
    fixed_parameters['capabilities_information'] = bitmap_value_for_dict(capabilities_information, capabilities_information_list)
    return fixed_parameters, offset

def tagged_parameters(frame: bytes, offset: int) -> (dict, int):
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
                "data": data.hex()
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

def eapol(frame: bytes, offset: int) -> dict:
    def _parse_key_data(key_data: bytes):
        result = {}
        _offset = 0
        key_data_len = len(key_data)
        while _offset < key_data_len:
            (elem_id, elem_len), _offset = unpack("BB", key_data, _offset)
            if _offset + elem_len > key_data_len:
                break
            elem_data, _offset = unpack(f"{offset + elem_len}s", key_data, _offset)
            if elem_id == TAG_VENDOR_SPECIFIC:
                vendor_result = ies_parsers.vendor_specific_ie(elem_data)
                result.update(vendor_result)
            elif elem_id == TAG_RSN_INFORMATION:
                result["rsn_information"] = ies_parsers.rsn_information(elem_data, elem_len)
        return result
    try:
        result = {}
        (auth_ver, eapol_type, length), offset = unpack("!BBH", frame, offset)

        result.update({
            "authentication_version": auth_ver,
            "type": eapol_type,
            "header_length": length
        })

        (desc_type, key_info, key_len), offset = unpack("!BHH", frame, offset)

        key_descriptor_version = key_info & 0x0007
        key_type_bit = (key_info >> 3) & 0x01
        key_index = (key_info >> 4) & 0x03
        install_bit = (key_info >> 6) & 0x01
        ack_bit = (key_info >> 7) & 0x01
        mic_bit = (key_info >> 8) & 0x01
        secure_bit = (key_info >> 9) & 0x01
        error_bit = (key_info >> 10) & 0x01
        request_bit = (key_info >> 11) & 0x01
        encrypted_key_data = (key_info >> 12) & 0x01
        smk_message = (key_info >> 13) & 0x01

        version_map = {
            0: "Reserved (0)",
            1: "HMAC-MD5 + ARC4 (WPA1)",
            2: "HMAC-SHA1-128 + AES (WPA2/RSN)",
            3: "AES-128-CMAC + AES-128-GCMP (WPA3)",
            4: "Reserved (4)", 
            5: "Reserved (5)",
            6: "Reserved (6)",
            7: "Reserved (7)"
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
                    "description": "Group/SMK" if key_type_bit else "Pairwise"
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
            "key_length": key_len
        })

        unpacked, offset = unpack(f"!{EAPOL_REPLAY_COUNTER_LENGTH}s{EAPOL_NONCE_LENGTH}s{EAPOL_KEY_IV_LENGTH}s{EAPOL_KEY_RSC_LENGTH}s{EAPOL_KEY_ID_LENGTH}s{EAPOL_KEY_MIC_LENGTH}s{EAPOL_KEY_DATA_LENGTH_FIELD}", frame, offset)
        replay, nonce, iv, rsc, key_id, mic, data_len = unpacked

        result.update({
            "replay_counter": replay,
            "key_nonce": nonce.hex(),
            "key_iv": iv.hex(),
            "key_rsc": rsc.hex(),
            "key_id": key_id.hex(),
            "key_mic": mic.hex(),
            "key_data_length": data_len
        })

        if data_len > 0 and offset + data_len <= len(frame):
            key_data = frame[offset:offset + data_len]
            result["key_data"] = {"value": key_data.hex(), "data": _parse_key_data(key_data)}
            offset += data_len

        return result, offset

    except Exception as e:
        logger.debug(f"EAPOL Parser error: {e}", exc_info=True)
        return result, offset
