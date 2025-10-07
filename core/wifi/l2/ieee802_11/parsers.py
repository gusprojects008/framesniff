# General parsers for ieee802_11 frames
import struct
import binascii
import re
from core.common.useful_functions import (safe_unpack, bytes_for_mac)
from core.wifi.l2.ieee802_11 import ies_parsers

def mac_header(frame, offset, mac_vendor_resolver):
    def _get_frame_type_subtype_name(frame_type: int, subtype: int):
        type_names = {0: "Management", 1: "Control", 2: "Data"}
        subtype_names = {
            0: {0: "Association Request", 1: "Association Response", 2: "Reassociation Request",
                3: "Reassociation Response", 4: "Probe Request", 5: "Probe Response", 6: "Timing Advertisement",
                8: "Beacon", 9: "ATIM", 10: "Disassociation", 11: "Authentication", 12: "Deauthentication",
                13: "Action", 14: "Action No Ack"},
            1: {8: "Block Ack Request", 9: "Block Ack", 10: "PS-Poll", 11: "RTS", 12: "CTS",
                13: "ACK", 14: "CF-End", 15: "CF-End+CF-Ack"},
            2: {i: name for i, name in enumerate([
                "Data", "Data+CF-Ack", "Data+CF-Poll", "Data+CF-Ack+CF-Poll", "Null",
                "CF-Ack", "CF-Poll", "CF-Ack+CF-Poll", "QoS Data", "QoS Data+CF-Ack",
                "QoS Data+CF-Poll", "QoS Data+CF-Ack+CF-Poll", "QoS Null", "Reserved",
                "QoS CF-Poll", "QoS CF-Ack+CF-Poll"])}
        }
        type_name = type_names.get(frame_type, f"Unknown ({frame_type})")
        subtype_name = subtype_names.get(frame_type, {}).get(subtype, f"Unknown {type_name} ({subtype})")
        return type_name, subtype_name

    mac_data = {}

    try:
        unpacked, new_offset = safe_unpack("<HH6s6s6sH", frame, offset)
        if unpacked is None:
            return mac_data, offset
        frame_control, duration_id, addr1, addr2, addr3, sequence_number = unpacked
        offset = new_offset

        protocol_version = frame_control & 0b11
        frame_type = (frame_control >> 2) & 0b11
        frame_subtype = (frame_control >> 4) & 0b1111
        frame_type_name, frame_subtype_name = _get_frame_type_subtype_name(frame_type, frame_subtype)

        to_ds = (frame_control >> 8) & 1
        from_ds = (frame_control >> 9) & 1
        addr4 = None
        if to_ds and from_ds and offset + 6 <= len(frame):
            addr4 = frame[offset:offset+6]

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

        mac_data.update({
            "fc": {
                "protocol_version": protocol_version,
                "type": frame_type,
                "type_name": frame_type_name,
                "subtype": frame_subtype,
                "subtype_name": frame_subtype_name,
                "tods": to_ds,
                "fromds": from_ds,
            },
            "mac_receiver": mac_receiver,
            "mac_transmitter": mac_transmitter
        })

        if frame_type in [0, 2]:
            mac_data.update({
                "mac_src": mac_source,
                "mac_dst": mac_destination,
                "bssid": bssid,
                "sequence_number": sequence_number
            })
            if frame_type == 2 and frame_subtype >= 8:
                unpacked, new_offset = safe_unpack("<H", frame, offset)
                if unpacked is not None:
                    mac_data["qos_control"] = unpacked[0]
                    offset = new_offset

        return mac_data, offset

    except struct.error as error:
        mac_data['error'] = str(error)
        return mac_data, offset

def tagged_parameters(frame: bytes, offset: int) -> (dict, int):
    tagged_parameters = {
    }
    try:
        result, offset = safe_unpack("<QHH", frame, offset)
        if result is None:
            return tagged_parameters, offset

        timestamp, beacon_interval, capabilities_information = result
        tagged_parameters['timestamp'] = timestamp
        tagged_parameters['beacon_interval'] = beacon_interval
        tagged_parameters['capabilities_information'] = capabilities_information

        while offset < len(frame):
            result, offset = safe_unpack("<BB", frame, offset)
            if result is None:
                break
            tag_number, tag_length = result
            if offset + tag_length > len(frame):
                break

            data = frame[offset:offset + tag_length]
            offset += tag_length

            if tag_number == 0:
                tagged_parameters['ssid'] = data.decode(errors='ignore')
            elif tag_number == 1:
                tagged_parameters['supported_rates'] = [{'rate': r & 0x7F, 'basic': bool(r & 0x80)} for r in data]
            elif tag_number == 3:
                if tag_length >= 1:
                    tagged_parameters['current_channel'] = data[0]
            #elif tag_number == 5: # TIM info
             #    tagged_parameters['tim'] = tim_info
            #elif tag_number == 7:
                    #tagged_parameters['country_info'] = IEs
            elif tag_number == 32 and tag_length >= 1:
                tagged_parameters['power_constraint'] = data[0]
            elif tag_number == 35 and tag_length >= 2:
                tagged_parameters['tpc_report'] = {'tx_power': data[0], 'reserved': data[1]}
            #elif tag_number == 42 and tag_length >= 1:
             #  tagged_parameters['erp_info'] = 
            #elif tag_number == 45 and tag_length >= 26:
             #    tagged_parameters['ht_capabilities'] = ht_caps
            #elif tag_number == 48 and tag_length >= 2:
             #    tagged_parameters['rsn_info'] = rsn_info
            elif tag_number == 50:
                tagged_parameters['extended_supported_rates'] = [{'rate': r & 0x7F, 'basic': bool(r & 0x80)} for r in data]
            #elif tag_number == 61 and tag_length >= 22:
                #tagged_parameters['ht_information'] = ht_info
            #elif tag_number == 70 and tag_length >= 5:
                #tagged_parameters['rm_enabled_capabilities'] = rm_caps
            #elif tag_number == 127 and tag_length >= 1:
                #tagged_parameters['extended_capabilities'] = ext_caps
            elif tag_number == 221:
                if "vendor_specific" not in tagged_parameters:
                    tagged_parameters["vendor_specific"] = {}
                vendor_ie = ies_parsers.vendor_specific_ie(data)
                for oui, ie_list in vendor_ie.items():
                    if oui not in tagged_parameters["vendor_specific"]:
                        tagged_parameters["vendor_specific"][oui] = []
                    tagged_parameters["vendor_specific"][oui].extend(ie_list)
        return tagged_parameters, offset
    except struct.error as error:
        tagged_parameters['error'] = str(error)
        return tagged_parameters, offset

def llc(frame, offset):
    result = {}
    try:
        unpacked, new_offset = safe_unpack("!BBB3sH", frame, offset)
        if unpacked is None:
            return result, offset
        dsap, ssap, control, org_code, llc_type = unpacked
        offset = new_offset
        result.update({
            "dsap": hex(dsap),
            "ssap": hex(ssap),
            "control_field": control,
            "organization_code": bytes_for_mac(org_code),
            "type": hex(llc_type)
        })
        return result, offset
    except struct.error as error:
        result['error'] = str(error)
        return result, offset

def eapol(frame, offset):
    def _parse_key_data(key_data: bytes):
        result = {}
        pos = 0
        while pos < len(key_data):
            if pos + 2 > len(key_data):
                break
            elem_id = key_data[pos]
            elem_len = key_data[pos + 1]
            pos += 2
            if pos + elem_len > len(key_data):
                break
            elem_data = key_data[pos:pos + elem_len]
            if elem_id == 221:  # Vendor Specific IE
                vendor_result = ies_parsers.vendor_specific_ie(elem_data)
                result.update(vendor_result)
            elif elem_id == 48:  # RSN IE
                result["rsn_information"] = ies_parsers.rsn_capabilities(elem_data)
            pos += elem_len
        return result
    try:
        result = {}
        unpacked, new_offset = safe_unpack("!BBH", frame, offset)
        if unpacked is None:
            return result, offset
        auth_ver, eapol_type, length = unpacked
        offset = new_offset
        result.update({
            "authentication_version": auth_ver,
            "type": eapol_type,
            "header_length": length
        })
        unpacked, new_offset = safe_unpack("!BHH", frame, offset)
        if unpacked is None:
            return result, offset
        desc_type, key_info, key_len = unpacked
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
                "key_descriptor_version": version_map.get(key_info & 0x0007),
                "key_type": "Group/SMK" if (key_info >> 3) & 0x01 else "Pairwise",
                "key_index": (key_info >> 4) & 0x03,
                "install": bool((key_info >> 6) & 0x01),
                "key_ack": bool((key_info >> 7) & 0x01),
                "key_mic": bool((key_info >> 8) & 0x01),
                "secure": bool((key_info >> 9) & 0x01),
                "error": bool((key_info >> 10) & 0x01),
                "request": bool((key_info >> 11) & 0x01),
                "encrypted_key_data": bool((key_info >> 12) & 0x01),
                "smk_message": bool((key_info >> 13) & 0x01),
        },
            "key_length": key_len
        })
        offset = new_offset
        unpacked, new_offset = safe_unpack("!Q32s16s8s8s16sH", frame, offset)
        if unpacked is None:
            return result, offset
        replay, nonce, iv, rsc, key_id, mic, data_len = unpacked
        offset = new_offset
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
            result["key_data"] = [key_data.hex(), _parse_key_data(key_data)]
            offset += data_len

        return result, offset

    except struct.error as error:
        result['error'] = str(error)
        return result, offset
