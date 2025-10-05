import socket
import struct
import time
import json
import re
import binascii
from uuid import UUID   
from ....common.useful_functions import *
from ....common.filter_engine import apply_filters
from ..radiotap_header import RadiotapHeader
from ....common.sockets import create_raw_socket

class IEEE802_11:
    class Parsers:
        class IEs:
            def vendor_specific_ie(data: bytes):
                def _wps_vendor_ie(vendor_data: bytes):
                    ATTR_MAP = {
                        0x104A: "Version",
                        0x1012: "Device Name", 
                        0x1011: "Device Password ID",
                        0x1008: "Config Methods",
                        0x1021: "Manufacturer",
                        0x1023: "Model Name",
                        0x1024: "Model Number",
                        0x1044: "WPS State",
                        0x1047: "UUID-E",
                        0x103C: "RF Bands",
                        0x1049: "Vendor Extension",
                        0x1054: "Primary Device Type",
                        0x1057: "Selected Registrar",
                        0x1053: "Selected Registrar Config Methods",
                        0x100D: "Public Key",
                        0x1042: "Network Key",
                        0x1041: "Network Key Index",
                        0x1001: "AP Setup Locked",
                        0x101A: "Message Type",
                        0x1020: "MAC Address",
                        0x1032: "Response Type",
                        0x103E: "Registrar Config Methods",
                        0x1010: "Version2",
                        0x1045: "SSID",
                        0x102D: "Serial Number",
                        0x103B: "OS Version",
                        0x1033: "Association State",
                    }
                
                    WPS_STATES = {0x01: "Not Configured", 0x02: "Configured"}
                    MESSAGE_TYPES = {
                        0x04: "M4 Message", 0x05: "M5 Message", 0x06: "M6 Message",
                        0x07: "M7 Message", 0x08: "M8 Message", 0x0B: "WSC_ACK",
                        0x0C: "WSC_NACK", 0x0D: "WSC_DONE"
                    }
                    RESPONSE_TYPES = {
                        0x00: "Enrollee Info", 0x01: "Enrollee", 0x02: "Registrar",
                        0x03: "AP"
                    }
                    RF_BANDS = {0x01: "2.4 GHz", 0x02: "5 GHz", 0x03: "2.4 & 5 GHz"}
                    CONFIG_METHODS = {
                        0x0001: "USB", 0x0002: "Ethernet", 0x0004: "Label",
                        0x0008: "Display", 0x0010: "External NFC Token",
                        0x0020: "Integrated NFC Token", 0x0040: "NFC Interface",
                        0x0080: "Push Button", 0x0100: "Keypad"
                    }
                    DEVICE_PASSWORD_IDS = {
                        0x0000: "Default", 0x0001: "User Specified", 0x0002: "Machine Specified",
                        0x0003: "Rekey", 0x0004: "Push Button", 0x0005: "Registrar Specified"
                    }
                    DEVICE_CATEGORIES = {
                        0x0001: "Computer", 0x0002: "Input Device", 0x0003: "Print/Scan/FAX/Copy",
                        0x0004: "Camera", 0x0005: "Storage", 0x0006: "Network Infrastructure",
                        0x0007: "Display", 0x0008: "Multimedia", 0x0009: "Gaming",
                        0x000A: "Telephone", 0x000B: "Audio", 0x000F: "Other"
                    }
                
                    data_dict = {}
                    pos = 0
                    index = 0
                
                    while pos + 4 <= len(vendor_data):
                        attr_type, attr_len = struct.unpack(">HH", vendor_data[pos:pos+4])
                        pos += 4
                        attr_data = vendor_data[pos:pos+attr_len]
                        pos += attr_len
                
                        name = ATTR_MAP.get(attr_type, f"Unknown ({attr_type})")
                        value_hex = binascii.hexlify(attr_data).decode()
                
                        parsed = {}
                        if attr_type == 0x104A:  # Version
                            version_major = attr_data[0] >> 4
                            version_minor = attr_data[0] & 0x0F
                            parsed = {"version": f"{version_major}.{version_minor}"}
                        elif attr_type == 0x1044:  # WPS State
                            state_hex = attr_data[0]
                            state_desc = WPS_STATES.get(state_hex, f"Unknown ({state_hex:#x})")
                            parsed = {"state": state_desc, "value": state_hex}
                        elif attr_type == 0x1047:  # UUID-E
                            uuid_str = UUID(hex=value_hex)
                            parsed = {"uuid": uuid_str}
                        elif attr_type == 0x103C:  # RF Bands
                            band_hex = attr_data[0]
                            band_desc = RF_BANDS.get(band_hex, f"Unknown ({band_hex:#x})")
                            parsed = {"bands": band_desc, "Hex": f"0x{band_hex:02x}"}
                        elif attr_type == 0x1008:  # Config Methods
                            config_mask = struct.unpack(">H", attr_data)[0]
                            methods = [name for bit, name in CONFIG_METHODS.items() if config_mask & bit]
                            parsed = {"methods": methods, "Mask": f"0x{config_mask:04x}"}
                        elif attr_type == 0x1011:  # Device Password ID
                            pid = struct.unpack(">H", attr_data)[0]
                            pid_desc = DEVICE_PASSWORD_IDS.get(pid, f"Unknown ({pid:#x})")
                            parsed = {"password_id": pid_desc, "Hex": f"0x{pid:04x}"}
                        elif attr_type == 0x1049:  # Vendor Extension
                            parsed = {"sublayers": {}}
                            pos_sub = 0
                            sub_index = 0
                            while pos_sub + 4 <= len(attr_data):
                                sub_type, sub_len = struct.unpack(">HH", attr_data[pos_sub:pos_sub+4])
                                pos_sub += 4
                                sub_value = attr_data[pos_sub:pos_sub+sub_len]
                                pos_sub += sub_len
                                
                                sub_parsed = None
                                if sub_type == 0x1010:  # Version2
                                    version_major = sub_value[0] >> 4
                                    version_minor = sub_value[0] & 0x0F
                                    sub_parsed = f"{version_major}.{version_minor}"
                                elif sub_type == 0x0000:  # Vendor ID
                                    sub_parsed = f"{int.from_bytes(sub_value, 'big')}"
                                
                                parsed["sublayers"][f"{sub_index:02d}. Type 0x{sub_type:04x}"] = {
                                    "value": sub_value.hex(),
                                    "parsed": sub_parsed
                                }
                                sub_index += 1
                        elif attr_type == 0x101A:  # Message Type
                            msg_type = attr_data[0]
                            msg_desc = MESSAGE_TYPES.get(msg_type, f"Unknown ({msg_type:#x})")
                            parsed = {"type": msg_desc, "hex": f"0x{msg_type:02x}"}
                        elif attr_type == 0x1020:  # MAC Address
                            mac_str = bytes_for_mac(attr_data)
                            parsed = {"mac": mac_str}
                        elif attr_type == 0x1032:  # Response Type
                            resp_type = attr_data[0]
                            resp_desc = RESPONSE_TYPES.get(resp_type, f"Unknown ({resp_type:#x})")
                            parsed = {"response_type": resp_desc}
                        elif attr_type == 0x1054:  # Primary Device Type
                            category = struct.unpack(">H", attr_data[:2])[0]
                            oui = bytes_for_mac(attr_data[2:6])
                            subtype = struct.unpack(">H", attr_data[6:8])[0]
                            category_desc = DEVICE_CATEGORIES.get(category, f"Unknown ({category})")
                            parsed = {
                                "category": f"{category_desc} ({category})", 
                                "oui": oui, 
                                "subcategory": subtype,
                                #"full": f"{category}-{oui.replace(':', '')}-{subtype}"
                            }
                        elif attr_type in [0x1012, 0x1021, 0x1023, 0x1024, 0x102D]:  # Text fields
                            try:
                                text_value = attr_data.decode("utf-8").strip()
                                parsed = {"string": text_value}
                            except UnicodeDecodeError:
                                parsed = {"data": value_hex}
                        else:
                            try:
                                parsed = {"string": attr_data.decode("utf-8").strip()}
                            except UnicodeDecodeError:
                                parsed = {"data": value_hex}
                
                        data_dict[f"{index:02d}. {name}"] = {
                            "type": f"0x{attr_type:04x}",
                            "data": parsed
                        }
                        index += 1
                    return data_dict

                oui = bytes_for_mac(data[:3])
                vendor_type = data[3]
                vendor_data = data[4:]
                vendor_entry = {
                    #"oui": oui,
                    "type": vendor_type,
                }
                if oui == "00:50:f2" and vendor_type == 0x04:
                    vendor_entry["description"] = "Microsoft Corporation WPS"
                    vendor_entry["data"] = _wps_vendor_ie(vendor_data)
                else:
                    vendor_entry["description"] = "Generic Vendor Specific"
                    vendor_entry["data"] = vendor_data.hex()
                return {oui: [vendor_entry]}

        @staticmethod
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
                    elif tag_number == 5: # TIM info
                        if tag_length >= 3:
                            tim_info = {
                                'dtim_count': data[0],
                                'dtim_period': data[1],
                                'bitmap_control': data[2],
                                'partial_virtual_bitmap': data[3:].hex() if tag_length > 3 else '',
                                'multicast': bool(data[2] & 0x01),
                                'bitmap_offset': (data[2] >> 1) & 0x7F
                            }
                            tagged_parameters['tim'] = tim_info
                    elif tag_number == 7:
                        if tag_length >= 3:
                            country_info = {'country_code': data[:3].decode(errors='ignore'), 'environment': data[3] if tag_length > 3 else 0}
                            if tag_length > 4:
                                sub_elements = []
                                sub_offset = 4
                                while sub_offset + 3 <= tag_length:
                                    sub_elements.append({
                                        'first_channel': data[sub_offset],
                                        'num_channels': data[sub_offset + 1],
                                        'max_tx_power': data[sub_offset + 2]
                                    })
                                    sub_offset += 3
                                country_info['sub_elements'] = sub_elements
                            tagged_parameters['country_info'] = country_info
                    elif tag_number == 32 and tag_length >= 1:
                        tagged_parameters['power_constraint'] = data[0]
                    elif tag_number == 35 and tag_length >= 2:
                        tagged_parameters['tpc_report'] = {'tx_power': data[0], 'reserved': data[1]}
                    elif tag_number == 42 and tag_length >= 1:
                        tagged_parameters['erp_info'] = {
                            'non_erp_present': bool(data[0] & 0x01),
                            'use_protection': bool(data[0] & 0x02),
                            'barker_preamble_mode': bool(data[0] & 0x04)
                        }
                    elif tag_number == 45 and tag_length >= 26:
                        ht_caps = {}
                        if len(data) >= 2:
                            ht_caps_info = struct.unpack_from('<H', data)[0]
                            ht_caps['ldpc_coding_capable'] = bool(ht_caps_info & 0x0001)
                            ht_caps['supported_channel_width'] = bool(ht_caps_info & 0x0002)
                            ht_caps['sm_power_save'] = (ht_caps_info >> 2) & 0x03
                            ht_caps['green_field'] = bool(ht_caps_info & 0x0010)
                            ht_caps['short_gi_20mhz'] = bool(ht_caps_info & 0x0020)
                            ht_caps['short_gi_40mhz'] = bool(ht_caps_info & 0x0040)
                            ht_caps['tx_stbc'] = bool(ht_caps_info & 0x0080)
                            ht_caps['rx_stbc'] = (ht_caps_info >> 8) & 0x03
                            ht_caps['delayed_block_ack'] = bool(ht_caps_info & 0x1000)
                            ht_caps['max_amsdu_length'] = bool(ht_caps_info & 0x2000)
                            ht_caps['dsss_cck_40mhz'] = bool(ht_caps_info & 0x4000)
                            ht_caps['psmp_support'] = bool(ht_caps_info & 0x8000)
                        if len(data) >= 3:
                            ampdu_params = data[2]
                            ht_caps['max_rx_ampdu_length'] = ampdu_params & 0x03
                            ht_caps['mpdu_density'] = (ampdu_params >> 2) & 0x07
                        if len(data) >= 19:
                            mcs_set = data[3:19]
                            ht_caps['rx_mcs_set'] = mcs_set.hex()
                            if len(mcs_set) >= 10:
                                ht_caps['highest_supported_rate'] = struct.unpack_from('<H', mcs_set, 8)[0]
                                ht_caps['tx_mcs_set_defined'] = bool(mcs_set[10] & 0x01)
                                ht_caps['tx_rx_mcs_set_equal'] = bool(mcs_set[10] & 0x02)
                                ht_caps['max_tx_spatial_streams'] = (mcs_set[10] >> 2) & 0x03
                                ht_caps['unequal_modulation'] = bool(mcs_set[10] & 0x10)
                        if len(data) >= 21:
                            ht_ext_caps = struct.unpack_from('<H', data, 19)[0]
                            ht_caps['pco_support'] = bool(ht_ext_caps & 0x0001)
                            ht_caps['transition_time'] = (ht_ext_caps >> 1) & 0x03
                            ht_caps['mcs_feedback'] = (ht_ext_caps >> 4) & 0x03
                        if len(data) >= 25:
                            txbf_caps = struct.unpack_from('<I', data, 21)[0]
                            ht_caps['transmit_beamforming'] = bool(txbf_caps & 0x00000001)
                            ht_caps['receive_staggered_sounding'] = bool(txbf_caps & 0x00000002)
                            ht_caps['transmit_staggered_sounding'] = bool(txbf_caps & 0x00000004)
                        if len(data) >= 26:
                            asel_caps = data[25]
                            ht_caps['asel_capable'] = bool(asel_caps & 0x01)
                            ht_caps['explicit_csi_feedback_tx_asel'] = bool(asel_caps & 0x02)
                        tagged_parameters['ht_capabilities'] = ht_caps
                    elif tag_number == 48 and tag_length >= 2:
                        rsn_info = {}
                        rsn_info['version'] = struct.unpack_from('<H', data)[0]
                        if tag_length >= 8:
                            rsn_info['group_cipher'] = {'oui': data[2:5].hex(':'), 'cipher_type': data[5]}
                        if tag_length >= 10:
                            pairwise_count = struct.unpack_from('<H', data, 6)[0]
                            rsn_info['pairwise_cipher_count'] = pairwise_count
                            pairwise_list = []
                            pairwise_offset = 8
                            for i in range(pairwise_count):
                                if pairwise_offset + 4 <= tag_length:
                                    pairwise_list.append({'oui': data[pairwise_offset:pairwise_offset+3].hex(':'), 'cipher_type': data[pairwise_offset+3]})
                                    pairwise_offset += 4
                            rsn_info['pairwise_cipher_list'] = pairwise_list
                        if pairwise_offset + 2 <= tag_length:
                            akm_count = struct.unpack_from('<H', data, pairwise_offset)[0]
                            rsn_info['akm_suite_count'] = akm_count
                            akm_list = []
                            akm_offset = pairwise_offset + 2
                            for i in range(akm_count):
                                if akm_offset + 4 <= tag_length:
                                    akm_list.append({'oui': data[akm_offset:akm_offset+3].hex(':'), 'akm_type': data[akm_offset+3]})
                                    akm_offset += 4
                            rsn_info['akm_suite_list'] = akm_list
                        if akm_offset + 2 <= tag_length:
                            rsn_caps = struct.unpack_from('<H', data, akm_offset)[0]
                            rsn_info['capabilities'] = {
                                'pre_auth': bool(rsn_caps & 0x0001),
                                'no_pairwise': bool(rsn_caps & 0x0002),
                                'ptksa_replay_counter': (rsn_caps >> 2) & 0x03,
                                'gtksa_replay_counter': (rsn_caps >> 4) & 0x03,
                                'mgmt_frame_protection_required': bool(rsn_caps & 0x0040),
                                'mgmt_frame_protection_capable': bool(rsn_caps & 0x0080),
                                'joint_multi_band_rsna': bool(rsn_caps & 0x0100),
                                'peerkey_enabled': bool(rsn_caps & 0x0200)
                            }
                        tagged_parameters['rsn_info'] = rsn_info
                    elif tag_number == 50:
                        tagged_parameters['extended_supported_rates'] = [{'rate': r & 0x7F, 'basic': bool(r & 0x80)} for r in data]
                    elif tag_number == 61 and tag_length >= 22:
                        ht_info = {}
                        ht_info['primary_channel'] = data[0]
                        if len(data) >= 2:
                            subset1 = data[1]
                            ht_info['secondary_channel_offset'] = subset1 & 0x03
                            ht_info['supported_channel_width'] = bool(subset1 & 0x04)
                            ht_info['rifs_permitted'] = bool(subset1 & 0x08)
                        if len(data) >= 4:
                            subset2 = struct.unpack_from('<H', data, 2)[0]
                            ht_info['ht_protection'] = subset2 & 0x03
                            ht_info['non_greenfield_stas_present'] = bool(subset2 & 0x04)
                            ht_info['obss_non_ht_stas_present'] = bool(subset2 & 0x10)
                            ht_info['channel_center_freq_segment2'] = (subset2 >> 5) & 0x1FF
                        if len(data) >= 6:
                            subset3 = struct.unpack_from('<H', data, 4)[0]
                            ht_info['dual_beacon'] = bool(subset3 & 0x0040)
                            ht_info['dual_cts_protection'] = bool(subset3 & 0x0080)
                        if len(data) >= 22:
                            ht_info['basic_mcs_set'] = data[6:22].hex()
                        tagged_parameters['ht_information'] = ht_info
                    elif tag_number == 70 and tag_length >= 5:
                        rm_caps = {}
                        rm_caps['link_measurement'] = bool(data[0] & 0x01)
                        rm_caps['neighbor_report'] = bool(data[0] & 0x02)
                        rm_caps['parallel_measurements'] = bool(data[0] & 0x04)
                        rm_caps['repeated_measurements'] = bool(data[0] & 0x08)
                        rm_caps['beacon_passive_measurement'] = bool(data[0] & 0x10)
                        rm_caps['beacon_active_measurement'] = bool(data[0] & 0x20)
                        rm_caps['beacon_table_measurement'] = bool(data[0] & 0x40)
                        rm_caps['beacon_measurement_reporting'] = bool(data[0] & 0x80)
                        rm_caps['frame_measurement'] = bool(data[1] & 0x01)
                        rm_caps['channel_load_measurement'] = bool(data[1] & 0x02)
                        rm_caps['noise_histogram_measurement'] = bool(data[1] & 0x04)
                        rm_caps['statistics_measurement'] = bool(data[1] & 0x08)
                        rm_caps['lci_measurement'] = bool(data[1] & 0x10)
                        rm_caps['lci_azimuth'] = bool(data[1] & 0x20)
                        rm_caps['tx_stream_category_measurement'] = bool(data[1] & 0x40)
                        rm_caps['triggered_tx_stream_measurement'] = bool(data[1] & 0x80)
                        tagged_parameters['rm_enabled_capabilities'] = rm_caps
                    elif tag_number == 127 and tag_length >= 1:
                        ext_caps = {}
                        if len(data) >= 1:
                            ext_caps['bss_coexistence'] = bool(data[0] & 0x01)
                            ext_caps['extended_channel_switching'] = bool(data[0] & 0x04)
                            ext_caps['psmp_capability'] = bool(data[0] & 0x10)
                        if len(data) >= 3:
                            ext_caps['bss_transition'] = bool(data[2] & 0x08)
                        if len(data) >= 4:
                            ext_caps['interworking'] = bool(data[3] & 0x80)
                        tagged_parameters['extended_capabilities'] = ext_caps
                    elif tag_number == 221:
                        if "vendor_specific" not in tagged_parameters:
                            tagged_parameters["vendor_specific"] = {}
                        vendor_ie = IEEE802_11.Parsers.IEs.vendor_specific_ie(data)
                        for oui, ie_list in vendor_ie.items():
                            if oui not in tagged_parameters["vendor_specific"]:
                                tagged_parameters["vendor_specific"][oui] = []
                            tagged_parameters["vendor_specific"][oui].extend(ie_list)
                return tagged_parameters, offset
            except struct.error as error:
                tagged_parameters['error'] = str(error)
                return tagged_parameters, offset

        @staticmethod
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
    
        @staticmethod
        def eapol(frame, offset):
            result = {}
            try:
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
                offset = new_offset
                result.update({
                    "key_descriptor_type": desc_type,
                    "key_information": key_info,
                    "key_length": key_len
                })
        
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
                    result["key_data"] = key_data.hex()
                    offset += data_len
        
                return result, offset
        
            except struct.error as error:
                result['error'] = str(error)
                return result, offset

    class MacHeader:
        @staticmethod
        def parse(frame, offset):
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
        
                mac_receiver = bytes_for_mac(addr1)
                mac_transmitter = bytes_for_mac(addr2)
                bssid = bytes_for_mac(addr3)
                mac_source, mac_destination = None, None
        
                if to_ds == 0 and from_ds == 0:
                    mac_source, mac_destination = mac_transmitter, mac_receiver
                elif to_ds == 0 and from_ds == 1:
                    mac_source, mac_destination = bytes_for_mac(addr3), mac_receiver
                    bssid = mac_transmitter
                elif to_ds == 1 and from_ds == 0:
                    mac_source, mac_destination = mac_transmitter, bytes_for_mac(addr3)
                    bssid = mac_receiver
                elif to_ds == 1 and from_ds == 1:
                    mac_source, mac_destination = bytes_for_mac(addr4) if addr4 else mac_transmitter, bytes_for_mac(addr3)
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

        @staticmethod
        def build(frame_control: int = 0x0000, receiver_address: str = "ff:ff:ff:ff:ff:ff",
                  transmitter_address: str = "ff:ff:ff:ff:ff:ff", bssid: str = None,
                  duration: int = 0, sequence: int = 0):
            frame_control_bytes = struct.pack("<H", frame_control)
            duration_bytes = struct.pack("<H", duration)
            receiver_bytes = mac_for_bytes(receiver_address)
            transmitter_bytes = mac_for_bytes(transmitter_address)
            bssid_bytes = mac_for_bytes(bssid or transmitter_address)
            sequence_bytes = struct.pack("<H", sequence & 0xFFF)
            return frame_control_bytes + duration_bytes + receiver_bytes + transmitter_bytes + bssid_bytes + sequence_bytes
    
    class Management:
        class build:
            @staticmethod
            def tagged_parameters(ssid: str = "TestSSID", rates: list = None, **kwargs):
                if rates is None:
                    rates = [0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c]
                tagged_data = b""
                ie_ssid = ssid.encode("utf-8")
                tagged_data += struct.pack("<BB", 0, len(ie_ssid)) + ie_ssid
                ie_rates = b"".join(struct.pack("<B", rate // 500) for rate in calc_rates(rates))
                tagged_data += struct.pack("<BB", 1, len(ie_rates)) + ie_rates
                if 'channel' in kwargs:
                    channel = kwargs['channel']
                    tagged_data += struct.pack("<BB", 3, 1) + struct.pack("<B", channel)
                if 'tim' in kwargs:
                    tim_data = kwargs['tim']
                    tagged_data += struct.pack("<BB", 5, len(tim_data)) + tim_data
                if 'extended_rates' in kwargs:
                    ext_rates = kwargs['extended_rates']
                    ie_ext_rates = b"".join(struct.pack("<B", rate // 500) for rate in calc_rates(ext_rates))
                    tagged_data += struct.pack("<BB", 50, len(ie_ext_rates)) + ie_ext_rates
                return tagged_data
    
            @staticmethod
            def deauthentication():
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = RandomMac()
                bssid = src_mac
                reason_code = 0x0007
                radiotap = RadiotapHeader.build()
                frame_control = 0x00C0
                mac_header = MacHeader.build(frame_control, dst_mac, src_mac, bssid)
                reason = struct.pack("<H", reason_code)
                frame_bytes = radiotap + mac_header + reason
                return frame_bytes.hex()
    
            @staticmethod
            def probe_request():
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = RandomMac()
                bssid = dst_mac
                radiotap = RadiotapHeader.build()
                frame_control = 0x0040
                mac_header = MacHeader.build(frame_control, dst_mac, src_mac, bssid)
                tagged_params = Management.build.tagged_parameters()
                frame_bytes = radiotap + mac_header + tagged_params
                return frame_bytes.hex()
    
            @staticmethod
            def beacon():
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = RandomMac()
                bssid = src_mac
                radiotap = RadiotapHeader.build()
                frame_control = 0x0080
                mac_header = MacHeader.build(frame_control, dst_mac, src_mac, bssid)
                timestamp = struct.pack("<Q", int(time.time() * 1_000_000))
                beacon_interval = struct.pack("<H", 100)
                capabilities = struct.pack("<H", 0x0431)
                frame_body = timestamp + beacon_interval + capabilities
                tagged_params = Management.build.tagged_parameters()
                frame_bytes = radiotap + mac_header + frame_body + tagged_params
                return frame_bytes.hex()
    
            @staticmethod
            def authentication():
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = RandomMac()
                bssid = src_mac
                radiotap = RadiotapHeader.build()
                frame_control = 0x00B0
                mac_header = MacHeader.build(frame_control, dst_mac, src_mac, bssid)
                auth_algorithm = struct.pack("<H", 0x0000)
                auth_seq = struct.pack("<H", 0x0001)
                status_code = struct.pack("<H", 0x0000)
                frame_bytes = radiotap + mac_header + auth_algorithm + auth_seq + status_code
                return frame_bytes.hex()
    
            @staticmethod
            def association_request():
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = RandomMac()
                bssid = dst_mac
                radiotap = RadiotapHeader.build()
                frame_control = 0x0000
                mac_header = MacHeader.build(frame_control, dst_mac, src_mac, bssid)
                capabilities = struct.pack("<H", 0x0431)
                listen_interval = struct.pack("<H", 0x0001)
                frame_body = capabilities + listen_interval
                tagged_params = Management.build.tagged_parameters()
                frame_bytes = radiotap + mac_header + frame_body + tagged_params
                return frame_bytes.hex()

        @staticmethod
        def parse(frame, offset):
            body = {}
            tagged_parameters, tagged_parameters_offset = IEEE802_11.Parsers.tagged_parameters(frame, offset)
            body["tagged_parameters"] = tagged_parameters
            return body

    class Control:
        class build:
            @staticmethod
            def rts(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", duration: int = 0):
                pass

        @staticmethod
        def parse(frame, offset):
            pass
    
    class Data:
        class build:
            @staticmethod
            def basic(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", payload = b""):
                pass

        @staticmethod
        def parse(frame, offset):
            body = {}
            llc, llc_offset = IEEE802_11.Parsers.llc(frame, offset)
            body["llc"] = llc
            if llc.get("type", "") == "0x888e":
                eapol, eapol_offset = IEEE802_11.Parsers.eapol(frame, llc_offset)
                body["eapol"] = eapol
            return body

    @staticmethod
    def frames_parser(raw_frame: bytes) -> dict:
        parsed_frame = {}
        rt_hdr, rt_hdr_len = RadiotapHeader.parse(raw_frame)
        mac_hdr, mac_hdr_offset = IEEE802_11.MacHeader.parse(raw_frame, rt_hdr_len)
        if not mac_hdr:
            return parsed_frame
        parsed_frame = {'rt_hdr': rt_hdr, 'mac_hdr': mac_hdr}
        try:
            frame_type = mac_hdr.get("fc").get("type")
            subtype = mac_hdr.get("fc").get("subtype")
            if frame_type == 0:
                body = IEEE802_11.Management.parse(raw_frame, mac_hdr_offset)
                parsed_frame["body"] = body
            elif frame_type == 1:
                parsed_frame["body"] = {"error": "Control frame parser not implemented"}
            elif frame_type == 2:
                body = IEEE802_11.Data.parse(raw_frame, mac_hdr_offset)
                parsed_frame["body"] = body
            else:
                parsed_frame["body"] = {"error": f"Unknown frame type {frame_type}"}
        except Exception as error:
            parsed_frame["body"] = {"parser_error": str(error)}
        return parsed_frame

    @staticmethod
    def generate_22000(bitmask_message_pair: int = 2, ssid: str = None, input_file: str = None, output_file: str = "hashcat.22000", message_pair: int = 0):
        if not input_file:
            raise ValueError("Input file must be provided.")
    
        output_file = new_file_path("hashcat", ".22000", output_file)
        ssid_hex = ssid.encode("utf-8", errors="ignore").hex()
    
        with open(input_file, "r") as f:
            data = json.load(f)

        if bitmask_message_pair == 1:
            pmkid = clean_hex_string(data.get("pmkid", ""))
            mac_ap = clean_hex_string(data.get("mac_ap", ""))
            mac_client = clean_hex_string(data.get("mac_client", ""))
            if not all([ssid, pmkid, mac_ap, mac_client]):
                raise ValueError("Missing one or more required keys: pmkid, mac_ap, mac_client")
            line = f"WPA*01*{pmkid}*{mac_ap}*{mac_client}*{ssid_hex}***{message_pair:02x}"
            print(line)
    
        elif bitmask_message_pair == 2:
            eapol_msg1_hex = None
            eapol_msg2_hex = None
            seen = 0
    
            for hexstr, _ in iter_packets_from_json(input_file):
                if seen == 0:
                    eapol_msg1_hex = hexstr
                elif seen == 1:
                    eapol_msg2_hex = hexstr
                    break
                seen += 1
    
            if eapol_msg1_hex is None:
                raise ValueError("No frames found in input file")
            if eapol_msg2_hex is None:
                raise ValueError("Only one frame found in input file; need two EAPOL frames")

            msg1 = bytes.fromhex(eapol_msg1_hex)
            msg2 = bytes.fromhex(eapol_msg2_hex)
    
            _, rth_len1 = RadiotapHeader.parse(msg1)
            mac_hdr1, mac_offset1 = IEEE802_11.MacHeader.parse(msg1, rth_len1)
            body1 = IEEE802_11.Data.parse(msg1, mac_offset1)
    
            _, rth_len2 = RadiotapHeader.parse(msg2)
            mac_hdr2, mac_offset2 = IEEE802_11.MacHeader.parse(msg2, rth_len2)
            body2 = IEEE802_11.Data.parse(msg2, mac_offset2)
    
            mac_ap = clean_hex_string(mac_hdr2.get("bssid", "") or mac_hdr2.get("mac_dst", ""))
            mac_client = clean_hex_string(mac_hdr2.get("mac_src", "") or mac_hdr2.get("mac_transmitter", ""))
    
            eapol_data1 = body1.get("eapol", {})
            eapol_data2 = body2.get("eapol", {})
    
            anonce = eapol_data1.get("key_nonce", "")
            mic = eapol_data2.get("key_mic", "")
            if not all([mac_ap, mac_client, anonce, mic]):
                raise ValueError("Missing essential EAPOL data")
            if len(mic) != 32:
                raise ValueError(f"Invalid MIC length: {len(mic)}")
            if len(anonce) != 64:
                raise ValueError(f"Invalid ANonce length: {len(anonce)}")
    
            essid = ssid.encode("utf-8", errors="ignore").hex()
    
            llc, llc_offset = IEEE802_11.Parsers.llc(msg2, mac_offset2)
            eapol_frame, eapol_frame_offset = IEEE802_11.Parsers.eapol(msg2, llc_offset)
            eapol_frame = msg2[llc_offset:eapol_frame_offset]
    
            mic_offset = struct.calcsize("!BBHBHHQ32s16s8s8s")
            mic_bytes = eapol_frame[mic_offset:mic_offset + struct.calcsize("16s")]
            zero_mic = b"\x00" * len(mic_bytes)
    
            eapol_zero_mic = (eapol_frame[:mic_offset] + zero_mic + eapol_frame[mic_offset + len(mic_bytes):]).hex()
            message_pair_hex = f"{message_pair:02x}"
    
            line = f"WPA*02*{mic}*{mac_ap}*{mac_client}*{essid}*{anonce}*{eapol_zero_mic}*{message_pair_hex}"
    
            with open(output_file, "w", newline="\n") as f:
                f.write(line)

            print(line)
        else:
            raise ValueError("Unsupported bitmask_message_pair. Must be 1 or 2.")
