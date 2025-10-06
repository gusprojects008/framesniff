# parsers for element informations IEs
from uuid import UUID
import binascii
import struct
from core.common.useful_functions import (safe_unpack, bytes_for_mac)

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
                uuid_str = str(UUID(hex=value_hex))
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

def rsn_capabilities(data: bytes) -> dict:
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

def tim_info(data: bytes):
    if tag_length >= 3:
        tim_info = {
            'dtim_count': data[0],
            'dtim_period': data[1],
            'bitmap_control': data[2],
            'partial_virtual_bitmap': data[3:].hex() if tag_length > 3 else '',
            'multicast': bool(data[2] & 0x01),
            'bitmap_offset': (data[2] >> 1) & 0x7F
       }
    return tim_info

def country_code(data: bytes):
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
    return country_info

def erp_info(data: bytes):
    return  {
        'non_erp_present': bool(data[0] & 0x01),
        'use_protection': bool(data[0] & 0x02),
        'barker_preamble_mode': bool(data[0] & 0x04)
    }

def ht_capabilities(data: bytes) -> dict:
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
    return ht_caps

def rm_enable_capabilities(data: bytes) -> dict:
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
    return rm_caps

def extended_capabilities(data: bytes) -> dict:
    ext_caps = {}
    if len(data) >= 1:
        ext_caps['bss_coexistence'] = bool(data[0] & 0x01)
        ext_caps['extended_channel_switching'] = bool(data[0] & 0x04)
        ext_caps['psmp_capability'] = bool(data[0] & 0x10)
    if len(data) >= 3:
        ext_caps['bss_transition'] = bool(data[2] & 0x08)
    if len(data) >= 4:
        ext_caps['interworking'] = bool(data[3] & 0x80)
    return ext_caps
