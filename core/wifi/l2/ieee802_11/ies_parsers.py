# parsers for element informations IEs
from uuid import UUID
import binascii
import struct
from core.common.useful_functions import (safe_unpack, bytes_for_mac)

def vendor_specific_ie(data: bytes):
    def _wps_vendor_ie(vendor_data: bytes):
        attr_map = {
            "version": 0x104a,
            "device_name": 0x1012,
            "device_password_id": 0x1011,
            "config_methods": 0x1008,
            "manufacturer": 0x1021,
            "model_name": 0x1023,
            "model_number": 0x1024,
            "wps_state": 0x1044,
            "uuid_e": 0x1047,
            "rf_bands": 0x103c,
            "vendor_extension": 0x1049,
            "primary_device_type": 0x1054,
            "selected_registrar": 0x1057,
            "selected_registrar_config_methods": 0x1053,
            "public_key": 0x100d,
            "network_key": 0x1042,
            "network_key_index": 0x1041,
            "ap_setup_locked": 0x1057,
            "message_type": 0x101a,
            "mac_address": 0x1020,
            "response_type": 0x1032,
            "registrar_config_methods": 0x103e,
            "version2": 0x1010,
            "ssid": 0x1045,
            "serial_number": 0x102d,
            "os_version": 0x103b,
            "association_state": 0x1033,
        }
        wps_states = {
            "not_configured": 0x01,
            "configured": 0x02,
        }
        message_types = {
            "m4_message": 0x04,
            "m5_message": 0x05,
            "m6_message": 0x06,
            "m7_message": 0x07,
            "m8_message": 0x08,
            "wsc_ack": 0x0b,
            "wsc_nack": 0x0c,
            "wsc_done": 0x0d,
        }
        response_types = {
            "enrollee_info": 0x00,
            "enrollee": 0x01,
            "registrar": 0x02,
            "ap": 0x03,
        }
        rf_bands = {
            "2_4_ghz": 0x01,
            "5_ghz": 0x02,
            "2_4_and_5_ghz": 0x03,
        }
        config_methods = {
            "usb": 0x0001,
            "ethernet": 0x0002,
            "label": 0x0004,
            "display": 0x0008,
            "external_nfc_token": 0x0010,
            "integrated_nfc_token": 0x0020,
            "nfc_interface": 0x0040,
            "push_button": 0x0080,
            "keypad": 0x0100,
        }
        device_password_ids = {
            "default": 0x0000,
            "user_specified": 0x0001,
            "machine_specified": 0x0002,
            "rekey": 0x0003,
            "push_button": 0x0004,
            "registrar_specified": 0x0005,
        }
        device_categories = {
            "computer": 0x0001,
            "input_device": 0x0002,
            "print_scan_fax_copy": 0x0003,
            "camera": 0x0004,
            "storage": 0x0005,
            "network_infrastructure": 0x0006,
            "display": 0x0007,
            "multimedia": 0x0008,
            "gaming": 0x0009,
            "telephone": 0x000a,
            "audio": 0x000b,
            "other": 0x000f,
        }
    
        result = {}
        pos = 0
        while pos + 4 <= len(vendor_data):
            (res, _offset) = safe_unpack(">HH", vendor_data, pos)
            if res is None:
                break
            attr_type, attr_len = res
            pos += 4
            if pos + attr_len > len(vendor_data):
                break
            attr_data = vendor_data[pos:pos+attr_len]
            pos += attr_len
    
            if attr_type == attr_map["version"]:
                (ver_res, _) = safe_unpack("B", attr_data, 0)
                if ver_res is not None:
                    (version_byte,) = ver_res
                    version_major = version_byte >> 4
                    version_minor = version_byte & 0x0F
                    result["version"] = f"{version_major}.{version_minor}"
            elif attr_type == attr_map["wps_state"]:
                (state_res, _) = safe_unpack("B", attr_data, 0)
                if state_res is not None:
                    (state_hex,) = state_res
                    state_desc = next((k for k, v in wps_states.items() if v == state_hex), f"unknown_{state_hex:02x}")
                    result["wps_state"] = state_desc
                    result["wps_state_value"] = state_hex
            elif attr_type == attr_map["ap_setup_locked"]:
                (locked_res, _) = safe_unpack("B", attr_data, 0)
                if locked_res is not None:
                    (locked_byte,) = locked_res
                    result["ap_setup_locked"] = locked_byte
            elif attr_type == attr_map["response_type"]:
                (resp_res, _) = safe_unpack("B", attr_data, 0)
                if resp_res is not None:
                    (resp_type,) = resp_res
                    resp_desc = next((k for k, v in response_types.items() if v == resp_type), f"unknown_{resp_type:02x}")
                    result["response_type"] = resp_desc
                    result["response_type_value"] = resp_type
            elif attr_type == attr_map["uuid_e"]:
                if len(attr_data) == 16:
                    result["uuid"] = str(UUID(bytes=attr_data))
                else:
                    result["uuid"] = attr_data.hex()
            elif attr_type == attr_map["manufacturer"]:
                result["manufacturer"] = attr_data.decode(errors="ignore").strip()
            elif attr_type == attr_map["model_name"]:
                result["model"] = attr_data.decode(errors="ignore").strip()
            elif attr_type == attr_map["model_number"]:
                result["model_number"] = attr_data.decode(errors="ignore").strip()
            elif attr_type == attr_map["serial_number"]:
                result["serial_number"] = attr_data.decode(errors="ignore").strip()
            elif attr_type == attr_map["device_name"]:
                result["device_name"] = attr_data.decode(errors="ignore").strip()
            elif attr_type == attr_map["primary_device_type"]:
                (cat_res, _) = safe_unpack(">H", attr_data, 0)
                if cat_res is not None:
                    (category,) = cat_res
                    oui = attr_data[2:6].hex()
                    (subtype_res, _) = safe_unpack(">H", attr_data, 6)
                    subtype = subtype_res[0] if subtype_res else None
                    result["primary_device_type"] = f"{category}-{oui}-{subtype}"
                    category_desc = next((k for k, v in device_categories.items() if v == category), f"unknown_{category:04x}")
                    result["primary_device_type_category"] = category_desc
                    result["primary_device_type_subcategory"] = subtype
            elif attr_type == attr_map["config_methods"]:
                (cfg_res, _) = safe_unpack(">H", attr_data, 0)
                if cfg_res is not None:
                    (config_mask,) = cfg_res
                    methods = [k.replace('_', ' ').title() for k, bit in config_methods.items() if config_mask & bit]
                    result["config_methods"] = ", ".join(methods)
                    result["config_methods_value"] = config_mask
            elif attr_type == attr_map["rf_bands"]:
                (band_res, _) = safe_unpack("B", attr_data, 0)
                if band_res is not None:
                    (band_hex,) = band_res
                    band_desc = next((k for k, v in rf_bands.items() if v == band_hex), f"unknown_{band_hex:02x}")
                    result["rf_bands"] = band_desc.replace('_', ' ').replace('ghz', 'GHz')
                    result["rf_bands_value"] = band_hex
            elif attr_type == attr_map["vendor_extension"]:
                vendor_id = int.from_bytes(attr_data[:3], "big")
                wfa_extension = attr_data[3:]
                _pos = 0
                while _pos + 2 <= len(wfa_extension):
                    wfa_ext_subelement_id, wfa_ext_subelement_len = struct.unpack_from(">BB", wfa_extension, _pos)
                    _pos += 2
                    if _pos + wfa_ext_subelement_len > len(wfa_extension):
                        break
                    wfa_ext_subelement = wfa_extension[_pos:_pos + wfa_ext_subelement_len]
                    _pos += wfa_ext_subelement_len
                    if wfa_ext_subelement_id == 0:  # Version2
                        version_major = wfa_ext_subelement[0] >> 4
                        version_minor = wfa_ext_subelement[0] & 0x0F
                        result["version2"] = f"{version_major}.{version_minor}"
                        break
        return result

    oui = bytes_for_mac(data[:3])
    vendor_type = data[3]
    vendor_data = data[4:]
    vendor_entry = {
        "oui": oui,
        "type": vendor_type,
    }
    
    if oui == "00:50:f2" and vendor_type == 0x04:
        vendor_entry["description"] = "Microsoft Corporation WPS"
        vendor_entry["data"] = _wps_vendor_ie(vendor_data)
    
    elif oui == "00:0f:ac" and vendor_type in [1, 2]:
        vendor_entry["description"] = "RSN Information"
        vendor_entry["data"] = rsn_capabilities(vendor_data)
    
    elif oui == "00:0f:ac" and vendor_type == 4:
        vendor_entry["description"] = "PMKID"
        if len(vendor_data) >= 16:
            vendor_entry["pmkid"] = vendor_data[:16].hex()
        else:
            vendor_entry["data"] = vendor_data.hex()
    
    else:
        vendor_entry["description"] = "Generic Vendor Specific"
        vendor_entry["data"] = vendor_data.hex()
    
    return {oui: [vendor_entry]}

def rsn_capabilities(data: bytes) -> dict:
    result = {}
   
    if len(data) < 2:
        return result
    
    result['version'] = struct.unpack_from('<H', data, 0)[0]
    pos = 2
    
    if pos + 4 <= len(data):
        result['group_cipher'] = {
            'oui': data[pos:pos+3].hex(':'),
            'cipher_type': data[pos+3]
        }
        pos += 4
    
    if pos + 2 <= len(data):
        pairwise_count = struct.unpack_from('<H', data, pos)[0]
        result['pairwise_cipher_count'] = pairwise_count
        pos += 2
        
        pairwise_list = []
        for i in range(pairwise_count):
            if pos + 4 <= len(data):
                pairwise_list.append({
                    'oui': data[pos:pos+3].hex(':'),
                    'cipher_type': data[pos+3]
                })
                pos += 4
        result['pairwise_cipher_list'] = pairwise_list
    
    if pos + 2 <= len(data):
        akm_count = struct.unpack_from('<H', data, pos)[0]
        result['akm_suite_count'] = akm_count
        pos += 2
        
        akm_list = []
        for i in range(akm_count):
            if pos + 4 <= len(data):
                akm_list.append({
                    'oui': data[pos:pos+3].hex(':'),
                    'akm_type': data[pos+3]
                })
                pos += 4
        result['akm_suite_list'] = akm_list
    
    if pos + 2 <= len(data):
        rsn_caps = struct.unpack_from('<H', data, pos)[0]
        result['capabilities'] = {
            'pre_auth': bool(rsn_caps & 0x0001),
            'no_pairwise': bool(rsn_caps & 0x0002),
            'ptksa_replay_counter': (rsn_caps >> 2) & 0x03,
            'gtksa_replay_counter': (rsn_caps >> 4) & 0x03,
            'mgmt_frame_protection_required': bool(rsn_caps & 0x0040),
            'mgmt_frame_protection_capable': bool(rsn_caps & 0x0080),
            'joint_multi_band_rsna': bool(rsn_caps & 0x0100),
            'peerkey_enabled': bool(rsn_caps & 0x0200)
        }
        pos += 2
    
    if pos + 2 <= len(data):
        pmkid_count = struct.unpack_from('<H', data, pos)[0]
        result['pmkid_count'] = pmkid_count
        pos += 2
        
        pmkid_list = []
        for i in range(pmkid_count):
            if pos + 16 <= len(data):
                pmkid = data[pos:pos+16].hex()
                pmkid_list.append(pmkid)
                pos += 16
        if pmkid_list:
            result['pmkids'] = pmkid_list
    
    return result

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
