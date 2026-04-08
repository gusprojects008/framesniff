from uuid import UUID
from logging import getLogger
from core.common.constants.ieee802_11 import *
from core.common.constants.l2 import *
from core.common.parser_utils import (unpack, bytes_for_mac)

logger = getLogger(__name__)

def ssid(data: bytes, tag_length: int) -> str:
    return data.decode(errors="ignore")

def tcp_report(data: bytes, tag_length: int) -> dict:
    return {'tx_power': data[0], 'reserved': data[1]} if len(data) >= 2 else {}

def power_constraint(data: bytes, tag_length: int) -> int:
    return data[0]

def current_channel(data: bytes, tag_length: int) -> int:
    return data[0]

def vendor_specific_ie(data: bytes, tag_length: int):
    def _wps_extension(vendor_data: bytes) -> dict:
        vendor_data_len = len(vendor_data) 
        offset = 0
        result = {}
    
        while offset + 4 <= vendor_data_len:
            (attr_type, attr_len), offset = unpack(">HH", vendor_data, offset)
            logger.debug(f"Parsing WPS attribute: type=0x{attr_type:04x}, len={attr_len}")
            
            if offset > vendor_data_len:
                logger.debug(f"WPS attribute truncated")
                break
                
            attr_data, offset = unpack(f"{attr_len}s", vendor_data, offset)
            attr_data_len = len(attr_data)
    
            if attr_type == WPS_ATTRIBUTE_IDS.get("version"):
                if attr_data_len >= 1:
                    version_byte = attr_data[0]
                    version_major = version_byte >> 4
                    version_minor = version_byte & 0x0F
                    result["version"] = f"{version_major}.{version_minor}"
                    
            elif attr_type == WPS_ATTRIBUTE_IDS.get("wps_state"):
                if attr_data_len >= 1:
                    state_hex = attr_data[0]
                    state_desc = next((k for k, v in WPS_CONFIGURATION_STATES.items() if v == state_hex), f"unknown_{state_hex:02x}")
                    result["wps_state"] = state_desc
                    result["wps_state_value"] = state_hex
                    
            elif attr_type == WPS_ATTRIBUTE_IDS.get("ap_setup_locked"):
                if attr_data_len >= 1:
                    result["ap_setup_locked"] = attr_data[0]
                    
            elif attr_type == WPS_ATTRIBUTE_IDS.get("response_type"):
                if attr_data_len >= 1:
                    resp_type = attr_data[0]
                    resp_desc = next((k for k, v in WPS_RESPONSE_TYPES.items() if v == resp_type), f"unknown_{resp_type:02x}")
                    result["response_type"] = resp_desc
                    result["response_type_value"] = resp_type
                    
            elif attr_type == WPS_ATTRIBUTE_IDS.get("uuid_e"):
                if attr_data_len == 16:
                    result["uuid"] = str(UUID(bytes=attr_data))
                else:
                    result["uuid"] = attr_data.hex()
                    
            elif attr_type == WPS_ATTRIBUTE_IDS.get("manufacturer"):
                result["manufacturer"] = attr_data.decode('utf-8', errors='ignore').strip('\x00')
                
            elif attr_type == WPS_ATTRIBUTE_IDS.get("model_name"):
                result["model"] = attr_data.decode('utf-8', errors='ignore').strip('\x00')
                
            elif attr_type == WPS_ATTRIBUTE_IDS.get("model_number"):
                result["model_number"] = attr_data.decode('utf-8', errors='ignore').strip('\x00')
                
            elif attr_type == WPS_ATTRIBUTE_IDS.get("serial_number"):
                result["serial_number"] = attr_data.decode('utf-8', errors='ignore').strip('\x00')
                
            elif attr_type == WPS_ATTRIBUTE_IDS.get("device_name"):
                result["device_name"] = attr_data.decode('utf-8', errors='ignore').strip('\x00')
                
            elif attr_type == WPS_ATTRIBUTE_IDS.get("primary_device_type"):
                if attr_data_len >= 8:
                    category = int.from_bytes(attr_data[0:2], 'big')
                    oui_bytes = attr_data[2:6]
                    oui = bytes_for_mac(oui_bytes)
                    subtype = int.from_bytes(attr_data[6:8], 'big')
                    result["primary_device_type"] = f"{category}-{oui}-{subtype}"
                    category_desc = next((k for k, v in WPS_DEVICE_CATEGORIES.items() if v == category), f"unknown_{category:04x}")
                    result["primary_device_type_category"] = category_desc
                    result["primary_device_type_subcategory"] = subtype
                    
            elif attr_type == WPS_ATTRIBUTE_IDS.get("config_methods"):
                if attr_data_len >= 2:
                    config_mask = int.from_bytes(attr_data[0:2], 'big')
                    methods = [k.replace('_', ' ').title() for k, bit in WPS_CONFIG_METHODS.items() if config_mask & bit]
                    result["config_methods"] = ", ".join(methods)
                    result["config_methods_value"] = config_mask
                    
            elif attr_type == WPS_ATTRIBUTE_IDS.get("rf_bands"):
                if attr_data_len >= 1:
                    band_hex = attr_data[0]
                    band_desc = next((k for k, v in WPS_RF_BANDS.items() if v == band_hex), f"unknown_{band_hex:02x}")
                    result["rf_bands"] = band_desc
                    result["rf_bands_value"] = band_hex
                    
            elif attr_type == WPS_ATTRIBUTE_IDS.get("vendor_extension"):
                if attr_data_len >= 4:
                    vendor_id = int.from_bytes(attr_data[0:3], 'big')
                    result["vendor_id"] = vendor_id
                    
                    sub_offset = 3
                    while sub_offset + 2 <= attr_data_len:
                        subelement_id = attr_data[sub_offset]
                        subelement_len = attr_data[sub_offset + 1]
                        sub_offset += 2
                        
                        if sub_offset + subelement_len > attr_data_len:
                            break
                            
                        subelement_data = attr_data[sub_offset:sub_offset+subelement_len]
                        sub_offset += subelement_len
                        
                        if subelement_id == 0:  # Version2
                            if len(subelement_data) >= 1:
                                version_major = subelement_data[0] >> 4
                                version_minor = subelement_data[0] & 0x0F
                                result["version2"] = f"{version_major}.{version_minor}"
                        elif subelement_id == 1:  # Request to Enroll
                            if len(subelement_data) >= 1:
                                result["request_to_enroll"] = bool(subelement_data[0] & 0x01)
        return result

    def _wmm_wme_extension(vendor_data: bytes) -> dict:
        result = {}
        offset = 0
        vendor_data_len = len(vendor_data)
        
        if vendor_data_len < 4:
            return result
        
        result["wme_subtype"], offset = unpack("B", vendor_data, offset)
        result["wme_version"], offset = unpack("B", vendor_data, offset)
        result["qos_info"], offset = unpack("B", vendor_data, offset)
        result["reserved"], offset = unpack("B", vendor_data, offset)
        
        ac_params = {}
        
        while offset + 4 <= vendor_data_len:
            aci_aifsn, offset = unpack("B", vendor_data, offset)
            ecw, offset = unpack("B", vendor_data, offset)
            txop, offset = unpack("<H", vendor_data, offset)
            
            ac_id = (aci_aifsn >> 5) & 0x03
            
            ac_info = {
                "ac": ac_id,
                "aifsn": aci_aifsn & 0x0F,
                "ecw_min": ecw & 0x0F,
                "ecw_max": (ecw >> 4) & 0x0F,
                "txop_limit": txop
            }
            
            ac_params[ac_id] = ac_info
        
        result["ac_parameters"] = ac_params
        return result

    logger.debug("Vendor specific parser: oui, vendor_type")
    
    oui_bytes, offset = unpack(f"3s", data)
    vendor_type, offset = unpack("B", data, offset)
    
    oui = bytes_for_mac(oui_bytes)
    vendor_data = data[offset:]

    vendor_entry = {
        "oui": oui,
        "type": vendor_type,
    }

    vendor_map = VENDOR_DESCRIPTION.get(oui, {})
    
    if isinstance(vendor_map, str):
        description = vendor_map
    else:
        description = vendor_map.get(vendor_type, "Generic Vendor Specific")

    vendor_entry["description"] = description
    vendor_entry["data"] = vendor_data.hex()

    logger.debug(f"Vendor specific parser: vendor_data for {oui}:{vendor_type}")

    if oui == OUI_MICROSOFT and vendor_type == MS_VENDOR_WPS:
        vendor_entry["parsed"] = _wps_extension(vendor_data)
    elif oui == OUI_MICROSOFT and vendor_type == MS_VENDOR_WMM_WME:
        vendor_entry["parsed"] = _wmm_wme_extension(vendor_data)
    elif oui == OUI_IEEE_80211 and vendor_type in [RSN_VENDOR_RSN_IE, RSN_VENDOR_RSN_IE_ALT]:
        vendor_entry["parsed"] = rsn_capabilities(vendor_data)
    elif oui == OUI_IEEE_80211 and vendor_type == RSN_VENDOR_PMKID:
        if len(vendor_data) >= EAPOL_PMKID_LENGTH:
            vendor_entry["parsed"] = vendor_data[:EAPOL_PMKID_LENGTH].hex()

    return vendor_entry

def rsn_information(data: bytes, tag_length: int) -> dict:
    logger.debug("RSN Information parser")
    result = {}

    if tag_length < 2:
        return result

    version, offset = unpack("<H", data)
    result['version'] = version

    if offset + 4 <= tag_length:
        group_oui, offset = unpack("3s", data, offset)
        group_cipher_type, offset = unpack("B", data, offset)
        result['group_cipher'] = {
            'oui': bytes_for_mac(group_oui),
            'cipher_type': group_cipher_type
        }
        logger.debug(f"Group cipher: {result['group_cipher']}")

    if offset + 2 <= tag_length:
        pairwise_count, offset = unpack("<H", data, offset)
        result['pairwise_cipher_count'] = pairwise_count
        
        pairwise_dict = {}
        for i in range(pairwise_count):
            if offset + 4 <= tag_length:
                pairwise_oui, offset = unpack("3s", data, offset)
                pairwise_type, offset = unpack("B", data, offset)
                pairwise_dict[i] = {
                    'oui': bytes_for_mac(pairwise_oui),
                    'cipher_type': pairwise_type
                }
        if pairwise_dict:
            result['pairwise_ciphers'] = pairwise_dict
            logger.debug(f"Pairwise ciphers: {pairwise_dict}")

    if offset + 2 <= tag_length:
        akm_count, offset = unpack("<H", data, offset)
        result['akm_suite_count'] = akm_count
        
        akm_dict = {}
        for i in range(akm_count):
            if offset + 4 <= tag_length:
                akm_oui, offset = unpack("3s", data, offset)
                akm_type, offset = unpack("B", data, offset)
                akm_dict[i] = {
                    'oui': bytes_for_mac(akm_oui),
                    'akm_type': akm_type
                }
        if akm_dict:
            result['akm_suites'] = akm_dict
            logger.debug(f"AKM suites: {akm_dict}")

    if offset + 2 <= tag_length:
        rsn_caps, offset = unpack("<H", data, offset)
        result['capabilities'] = {
            'pre_auth': bool(rsn_caps & 0x0001),
            'no_pairwise': bool(rsn_caps & 0x0002),
            'ptksa_replay_counter': (rsn_caps >> 2) & 0x03,
            'gtksa_replay_counter': (rsn_caps >> 4) & 0x03,
            'mgmt_frame_protection_required': bool(rsn_caps & 0x0040),
            'mgmt_frame_protection_capable': bool(rsn_caps & 0x0080),
            'joint_multi_band_rsna': bool(rsn_caps & 0x0100),
            'peerkey_enabled': bool(rsn_caps & 0x0200),
            'spp_amsdu_capable': bool(rsn_caps & 0x0400),
            'spp_amsdu_required': bool(rsn_caps & 0x0800),
            'pbac': bool(rsn_caps & 0x1000),
            'extended_key_id': bool(rsn_caps & 0x2000),
            'ocvc': bool(rsn_caps & 0x4000),
            'reserved': bool(rsn_caps & 0x8000)
        }
        logger.debug(f"RSN capabilities: {result['capabilities']}")

    if offset + 2 <= tag_length:
        pmkid_count, offset = unpack("<H", data, offset)
        result['pmkid_count'] = pmkid_count
        
        pmkids = {}
        for i in range(pmkid_count):
            if offset + EAPOL_PMKID_LENGTH <= tag_length:
                pmkid, offset = unpack(f"{EAPOL_PMKID_LENGTH}s").hex()
                pmkids[i] = pmkid
        if pmkids:
            result['pmkids'] = pmkids

    return result

def rates(frame: bytes, offset: int, tag_length: int) -> tuple[dict, int]:
    def _parse_rate(rate: int, raw: bytes, offset: int) -> tuple(dict, int):
       return {"value": (rate & 0x7F) / 2, "basic": bool(rate & 0x80)}, offset 
    rates_info = {}
    end = offset + tag_length
    i = 1
    while offset < end:
        field, offset = unpack("B", frame, offset, _parse_rate)
        rates_info[i] = field 
        i += 1
    return rates_info, offset

def tim_info(data: bytes, tag_length: int):
    tim = {}
    offset = 0

    if tag_length < 4:
        return tim

    dtim_count, offset = unpack('<B', data, offset)
    tim['dtim_count'] = dtim_count

    dtim_period, offset = unpack('<B', data, offset)
    tim['dtim_period'] = dtim_period

    bitmap_control, offset = unpack('<B', data, offset)

    tim['bitmap_control'] = bitmap_control
    tim['multicast'] = bool(bitmap_control & 0x01)
    tim['bitmap_offset'] = (bitmap_control >> 1) & 0x7F

    remaining_length = tag_length - offset

    if remaining_length > 0:
        partial_virtual_bitmap, offset = unpack(f'<{remaining_length}s', data, offset)
        tim['partial_virtual_bitmap'] = partial_virtual_bitmap.hex()
    else:
        tim['partial_virtual_bitmap'] = ''

    return tim

def country_code(data: bytes, tag_length: int):
    country_info = {
        'country_code': data[:3].decode(errors='ignore'),
        'environment': data[3] if tag_length > 3 else 0
    }
    if tag_length > 4:
        sub_elements = {}
        sub_offset = 4
        i = 0
        while sub_offset + 3 <= tag_length:
            sub_elements[i] = {
                'first_channel': data[sub_offset],
                'num_channels': data[sub_offset + 1],
                'max_tx_power': data[sub_offset + 2]
            }
            i += 1
            sub_offset += 3
        country_info['sub_elements'] = sub_elements
    return country_info

def erp_info(data: bytes, tag_length: int):
    if tag_length >= 1:
        return {
            'non_erp_present': bool(data[0] & 0x01),
            'use_protection': bool(data[0] & 0x02),
            'barker_preamble_mode': bool(data[0] & 0x04)
        }
    return {}

def ht_capabilities(data: bytes, tag_length: int) -> dict:
    ht = {}
    offset = 0

    if tag_length < 26:
        return ht

    ht_caps_info, offset = unpack('<H', data, offset)

    ht['ldpc_coding_capable'] = bool(ht_caps_info & 0x0001)
    ht['supported_channel_width'] = bool(ht_caps_info & 0x0002)
    ht['sm_power_save'] = (ht_caps_info >> 2) & 0x03
    ht['green_field'] = bool(ht_caps_info & 0x0010)
    ht['short_gi_20mhz'] = bool(ht_caps_info & 0x0020)
    ht['short_gi_40mhz'] = bool(ht_caps_info & 0x0040)
    ht['tx_stbc'] = bool(ht_caps_info & 0x0080)
    ht['rx_stbc'] = (ht_caps_info >> 8) & 0x03
    ht['delayed_block_ack'] = bool(ht_caps_info & 0x0400)
    ht['max_amsdu_length'] = bool(ht_caps_info & 0x0800)
    ht['dsss_cck_40mhz'] = bool(ht_caps_info & 0x1000)
    ht['forty_mhz_intolerant'] = bool(ht_caps_info & 0x4000)
    ht['lsig_txop_protection'] = bool(ht_caps_info & 0x8000)

    ampdu_params, offset = unpack('<B', data, offset)

    ht['max_rx_ampdu_length_exponent'] = ampdu_params & 0x03
    ht['min_mpdu_start_spacing'] = (ampdu_params >> 2) & 0x07

    rx_mcs_bitmask, offset = unpack('<10s', data, offset)
    ht['rx_mcs_bitmask'] = rx_mcs_bitmask.hex()

    highest_supported_rate, offset = unpack('<H', data, offset)
    ht['highest_supported_rate'] = highest_supported_rate

    tx_mcs_info, offset = unpack('<B', data, offset)

    ht['tx_mcs_set_defined'] = bool(tx_mcs_info & 0x01)
    ht['tx_rx_mcs_set_equal'] = bool(tx_mcs_info & 0x02)
    ht['max_tx_spatial_streams'] = (tx_mcs_info >> 2) & 0x03
    ht['unequal_modulation'] = bool(tx_mcs_info & 0x10)

    _, offset = unpack('<3s', data, offset)

    ht_ext_caps, offset = unpack('<H', data, offset)

    ht['pco_support'] = bool(ht_ext_caps & 0x0001)
    ht['pco_transition_time'] = (ht_ext_caps >> 1) & 0x03
    ht['mcs_feedback'] = (ht_ext_caps >> 4) & 0x03
    ht['htc_support'] = bool(ht_ext_caps & 0x0400)
    ht['reverse_direction_responder'] = bool(ht_ext_caps & 0x0800)

    txbf_caps, offset = unpack('<I', data, offset)

    ht['implicit_bf_rx'] = bool(txbf_caps & 0x00000001)
    ht['rx_staggered_sounding'] = bool(txbf_caps & 0x00000002)
    ht['tx_staggered_sounding'] = bool(txbf_caps & 0x00000004)
    ht['rx_ndp'] = bool(txbf_caps & 0x00000008)
    ht['tx_ndp'] = bool(txbf_caps & 0x00000010)

    asel_caps, offset = unpack('<B', data, offset)

    ht['asel_capable'] = bool(asel_caps & 0x01)
    ht['explicit_csi_feedback_tx_asel'] = bool(asel_caps & 0x02)
    ht['antenna_indices_feedback_tx_asel'] = bool(asel_caps & 0x04)
    ht['explicit_csi_feedback'] = bool(asel_caps & 0x08)
    ht['antenna_indices_feedback'] = bool(asel_caps & 0x10)
    ht['rx_asel'] = bool(asel_caps & 0x20)

    return ht

def rm_enable_capabilities(data: bytes, tag_length: int) -> dict:
    if tag_length >= 2:
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
    return {}

def extended_capabilities(data: bytes, tag_length: int) -> dict:
    ext_caps = {}
    if tag_length >= 1:
        ext_caps['bss_coexistence'] = bool(data[0] & 0x01)
        ext_caps['extended_channel_switching'] = bool(data[0] & 0x04)
        ext_caps['psmp_capability'] = bool(data[0] & 0x10)
    if tag_length >= 3:
        ext_caps['bss_transition'] = bool(data[2] & 0x08)
    if tag_length >= 4:
        ext_caps['interworking'] = bool(data[3] & 0x80)
    return ext_caps

def qbss_load_element(data: bytes, tag_length: int) -> dict:
    qbss_load_element_min_len = 5
    result = {}

    if tag_length < qbss_load_element_min_len:
        return result

    (station_count, channel_utilization, available_admission_capacity), _ = unpack("<HBH", data)

    result['station_count'] = station_count
    result['channel_utilization'] = channel_utilization
    result['available_admission_capacity'] = available_admission_capacity

    return result

IE_DISPATCH = {
    TAG_SSID: {
        "name": "ssid",
        "parser": ssid
    },
    TAG_SUPPORTED_RATES: {
        "name": "supported_rates",
        "parser": rates
    },
    TAG_RSN_INFORMATION: {
        "name": "rsn_information",
        "parser": rsn_information
    },
    TAG_TIM: {
        "name": "tim",
        "parser": tim_info
    },
    TAG_COUNTRY: {
        "name": "country",
        "parser": country_code
    },
    TAG_ERP: {
        "name": "erp_information",
        "parser": erp_info
    },
    TAG_EXTENDED_SUPPORTED_RATES: {
        "name": "extended_supported_rates",
        "parser": rates
    },
    TAG_VENDOR_SPECIFIC: {
        "name": "vendor_specific",
        "parser": vendor_specific_ie
    },
    TAG_HT_CAPABILITIES: {
        "name": "ht_capabilities",
        "parser": ht_capabilities
    },
    TAG_RM_ENABLED_CAPABILITIES: {
        "name": "rm_enabled_capabilities",
        "parser": rm_enable_capabilities
    },
    TAG_EXTENDED_CAPABILITIES: {
        "name": "extended_capabilities",
        "parser": extended_capabilities
    },
    TAG_QBSS_LOAD: {
        "name": "qbss_load",
        "parser": qbss_load_element
    },
    TAG_POWER_CONSTRAINT: {
      "name": "power_constraint",
      "parser": power_constraint
    },
    TAG_CURRENT_CHANNEL: {
      "name": "current_channel",
      "parser": current_channel
    }
}

def ie_dispatch(value: tuple[int | str], frame: bytes, offset: int):
    tag_number, tag_length = value
    result = {
        "tag_number": tag_number,
        "tag_length": tag_length,
    }
    entry = IE_DISPATCH.get(tag_number)
    ie_data = {}
    result["tag_name"] = entry.get("name", tag_number)
    parser = entry.get("parser")
    if parser:
        ie_data, offset = parser(frame, offset, tag_length)
    else:
        ie_data, offset = unpack(f"{tag_length}s", frame, offset)
    result.update(ie_data)
    return result, offset
