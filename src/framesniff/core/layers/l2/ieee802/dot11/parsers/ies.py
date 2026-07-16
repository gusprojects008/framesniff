import struct
from uuid import UUID
from logging import getLogger
from core.layers.l2.ieee802.dot11.constants import *
from core.layers.l2.constants import *
from core.common.parser import (ParseContext, unpack, run_dispatch, bytes_for_oui)

logger = getLogger(__name__)

TAG_SSID = 0
TAG_SUPPORTED_RATES = 1
TAG_CURRENT_CHANNEL = 3
TAG_TIM = 5
TAG_COUNTRY = 7
TAG_QBSS_LOAD = 11
TAG_POWER_CONSTRAINT = 32
TAG_TPC_REPORT = 35
TAG_ERP = 42
TAG_HT_CAPABILITIES = 45
TAG_RM_ENABLED_CAPABILITIES = 70
TAG_RSN_INFORMATION = 48
TAG_EXTENDED_SUPPORTED_RATES = 50
TAG_EXTENDED_CAPABILITIES = 127
TAG_VENDOR_SPECIFIC = 221
TAG_EXTENDED_HE = 255

OUI_MICROSOFT = "00:50:f2"
OUI_IEEE_80211 = "00:0f:ac"
OUI_WFA = "50:6f:9a"
OUI_MEDIATEK = "00:0c:43"
OUI_BROADCOM = "00:10:18"
OUI_ATHEROS = "00:03:7f"

MS_VENDOR_WPA = 1
MS_VENDOR_WPS = 4
MS_VENDOR_WMM_WME = 2

RSN_VENDOR_RSN_IE = 1
RSN_VENDOR_RSN_IE_ALT = 2
RSN_VENDOR_PMKID = 4

WFA_VENDOR_WPS = 4
WFA_VENDOR_P2P = 9
WFA_VENDOR_HS20 = 16
WFA_VENDOR_OSEN = 18

WPS_ATTRIBUTE_IDS = {
    "version": 0x104A,
    "device_name": 0x1012,
    "device_password_id": 0x1011,
    "config_methods": 0x1008,
    "manufacturer": 0x1021,
    "model_name": 0x1023,
    "model_number": 0x1024,
    "wps_state": 0x1044,
    "uuid_e": 0x1047,
    "rf_bands": 0x103C,
    "vendor_extension": 0x1049,
    "primary_device_type": 0x1054,
    "response_type": 0x103B,
    "serial_number": 0x1022,
}

WPS_CONFIGURATION_STATES = {
    "not_configured": 0x01,
    "configured": 0x02,
}

WPS_RESPONSE_TYPES = {
    "enrollee_info": 0x00,
    "enrollee": 0x01,
    "registrar": 0x02,
    "ap": 0x03,
}

WPS_RF_BANDS = {
    "2.4ghz": 0x01,
    "5ghz": 0x02,
    "2.4ghz_and_5ghz": 0x03,
}

WPS_CONFIG_METHODS = {
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

WPS_DEVICE_CATEGORIES = {
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

def _parse_wps_attribute(attr_type: int, attr_data: bytes) -> dict:
    result = {}

    if attr_type == WPS_ATTRIBUTE_IDS.get("version"):
        if len(attr_data) >= 1:
            version_byte = attr_data[0]
            version_major = version_byte >> 4
            version_minor = version_byte & 0x0F
            result["version"] = f"{version_major}.{version_minor}"

    elif attr_type == WPS_ATTRIBUTE_IDS.get("wps_state"):
        if len(attr_data) >= 1:
            state_hex = attr_data[0]
            state_desc = next(
                (k for k, v in WPS_CONFIGURATION_STATES.items() if v == state_hex),
                f"unknown_{state_hex:02x}"
            )
            result["wps_state"] = state_desc
            result["wps_state_value"] = state_hex

    elif attr_type == WPS_ATTRIBUTE_IDS.get("response_type"):
        if len(attr_data) >= 1:
            resp_type = attr_data[0]
            resp_desc = next(
                (k for k, v in WPS_RESPONSE_TYPES.items() if v == resp_type),
                f"unknown_{resp_type:02x}"
            )
            result["response_type"] = resp_desc
            result["response_type_value"] = resp_type

    elif attr_type == WPS_ATTRIBUTE_IDS.get("uuid_e"):
        if len(attr_data) == 16:
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
        if len(attr_data) >= 8:
            category = int.from_bytes(attr_data[0:2], 'big')
            oui = bytes_for_oui(attr_data[2:6]).get("oui")
            subtype = int.from_bytes(attr_data[6:8], 'big')
            result["primary_device_type"] = f"{category}-{oui}-{subtype}"
            category_desc = next(
                (k for k, v in WPS_DEVICE_CATEGORIES.items() if v == category),
                f"unknown_{category:04x}"
            )
            result["primary_device_type_category"] = category_desc
            result["primary_device_type_subcategory"] = subtype

    elif attr_type == WPS_ATTRIBUTE_IDS.get("config_methods"):
        if len(attr_data) >= 2:
            config_mask = int.from_bytes(attr_data[0:2], 'big')
            methods = [
                k.replace('_', ' ').title()
                for k, bit in WPS_CONFIG_METHODS.items()
                if config_mask & bit
            ]
            result["config_methods"] = ", ".join(methods)
            result["config_methods_value"] = config_mask

    elif attr_type == WPS_ATTRIBUTE_IDS.get("rf_bands"):
        if len(attr_data) >= 1:
            band_hex = attr_data[0]
            band_desc = next(
                (k for k, v in WPS_RF_BANDS.items() if v == band_hex),
                f"unknown_{band_hex:02x}"
            )
            result["rf_bands"] = band_desc
            result["rf_bands_value"] = band_hex

    elif attr_type == WPS_ATTRIBUTE_IDS.get("vendor_extension"):
        if len(attr_data) >= 3:
            vendor_id = int.from_bytes(attr_data[0:3], 'big')
            result["vendor_id"] = vendor_id

            sub_offset = 3
            while sub_offset + 2 <= len(attr_data):
                subelement_id = attr_data[sub_offset]
                subelement_len = attr_data[sub_offset + 1]
                sub_offset += 2

                if sub_offset + subelement_len > len(attr_data):
                    break

                subelement_data = attr_data[sub_offset:sub_offset + subelement_len]
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

def _wps_extension(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    end_offset = ctx.offset + (tag_length - 4)
    
    attributes = {}
    idx = 1

    while ctx.offset + 4 <= end_offset:
        def _attr_parser(value: tuple, **k) -> dict:
            attr_type, attr_len = value
            
            data_res = unpack(f"{attr_len}s")
            raw_data = data_res["value"]
            
            if isinstance(raw_data, str):
                raw_data = bytes.fromhex(raw_data)

            fields = _parse_wps_attribute(attr_type, raw_data)
            
            return {
                "attr_type": attr_type,
                "attr_length": attr_len,
                "fields": fields
            }

        attr_entry = unpack(">HH", parser=_attr_parser)
        attributes[idx] = attr_entry
        idx += 1

    return attributes

def _wmm_wme_extension(tag_length: int, **kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        subtype, version, qos_info, reserved = value
        
        ctx = ParseContext.current()
        end_offset = ctx.offset + (tag_length - 8) 
        
        ac_params = {}
        idx = 0

        while ctx.offset + 4 <= end_offset:
            def _ac_parser(ac_val: tuple, **ak) -> dict:
                aci_aifsn, ecw, txop = ac_val
                
                ac_id = (aci_aifsn >> 5) & 0x03
                aifsn = aci_aifsn & 0x0F
                ecw_min = ecw & 0x0F
                ecw_max = (ecw >> 4) & 0x0F
                
                return {
                    "ac_index": ac_id,
                    "aifsn": aifsn,
                    "ecw_min": ecw_min,
                    "ecw_max": ecw_max,
                    "txop_limit": txop
                }

            ac_entry = unpack("<BBH", parser=_ac_parser)
            key = ac_entry.get("parsed", {}).get("ac_index", idx)
            ac_params[key] = ac_entry
            idx += 1

        return {
            "wme_subtype": subtype,
            "wme_version": version,
            "qos_info": qos_info,
            "ac_parameters": ac_params
        }

    return unpack("BBBB", parser=_parser)

def _rsn_capabilities(tag_length: int, **kwargs) -> dict:
    def _parser(value: int, **k) -> dict:
        pre_auth = bool(value & 0x0001)
        no_pairwise = bool(value & 0x0002)
        ptksa_replay = (value >> 2) & 0x03
        gtksa_replay = (value >> 4) & 0x03
        mfp_required = bool(value & 0x0040)
        mfp_capable = bool(value & 0x0080)
        ocvc = bool(value & 0x4000)

        return {
            "pre_auth": pre_auth,
            "no_pairwise": no_pairwise,
            "ptksa_replay_counter_limit": ptksa_replay,
            "gtksa_replay_counter_limit": gtksa_replay,
            "management_frame_protection_required": mfp_required,
            "management_frame_protection_capable": mfp_capable,
            "ocvc": ocvc
        }

    return unpack("<H", parser=_parser)

SPECIFIC_VENDOR_DISPATCH = {
    OUI_MICROSOFT: {
        MS_VENDOR_WPS: {"description": "Wi-Fi Alliance WPS (Microsoft)", "parser": _wps_extension},
        MS_VENDOR_WMM_WME: {"description": "Microsoft WMM/WME", "parser": _wmm_wme_extension},
        MS_VENDOR_WPA: {"description": "Microsoft WPA", "parser": None}
    },
    OUI_IEEE_80211: {
        RSN_VENDOR_RSN_IE: {"description": "RSN Information", "parser": _rsn_capabilities},
        RSN_VENDOR_RSN_IE_ALT: {"description": "RSN Information (Alt)", "parser": _rsn_capabilities},
        RSN_VENDOR_PMKID: {"description": "PMKID", "parser": None}
    },
    OUI_WFA: {
        WFA_VENDOR_WPS: {"description": "Wi-Fi Alliance WPS", "parser": None},
        WFA_VENDOR_P2P: {"description": "Wi-Fi Alliance P2P", "parser": None},
        WFA_VENDOR_HS20: {"description": "Wi-Fi Alliance Hotspot 2.0", "parser": None},
        WFA_VENDOR_OSEN: {"description": "Wi-Fi Alliance OSEN", "parser": None}
    },
    OUI_MEDIATEK: {"description": "MediaTek Inc", "parser": None},
    OUI_BROADCOM: {"description": "Broadcom", "parser": None},
    OUI_ATHEROS: {"description": "Atheros", "parser": None}
}

def vendor_specific(tag_length: int, **kwargs) -> dict:
    fmt = f"{OUI_LENGTH}sB"

    def _parser(value: tuple, **kwargs) -> dict:
        oui, vtype = value
        oui = bytes_for_oui(oui)
        
        vendor_sub_table = SPECIFIC_VENDOR_DISPATCH.get(oui["oui"], {})
        entry = vendor_sub_table.get(vtype, {})
        description = entry.get("description", "Generic Vendor Specific")
        
        remaining_len = tag_length - struct.calcsize(fmt)

        def _fallback(**k):
            return unpack(f"{remaining_len}s")

        data = run_dispatch(
            dispatch_table=vendor_sub_table,
            dispatch_id=vtype,
            fallback=_fallback,
            tag_length=tag_length
        )

        result = {
            **oui,
            "vendor_type": vtype,
            "description": description,
            "data": data
        }
        return result

    return unpack(fmt, parser=_parser)

def ssid(tag_length: int, **kwargs) -> dict:
    return unpack(f"{tag_length}s", parser=lambda value: value.decode(errors="ignore"))

def rates(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    end = ctx.offset + tag_length

    result = {}
    i = 1

    while ctx.offset < end:
        rate_result = unpack(
            "B",
            parser=lambda value: {
                "value": (value & 0x7F) / 2,
                "basic": bool(value & 0x80)
            }
        )
        result[i] = rate_result
        i += 1

    return result

def tim_info(tag_length: int, **kwargs) -> dict:
    if tag_length < 4:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        dtim_count, dtim_period, bitmap_control = values
        
        multicast = bool(bitmap_control & 0x01)
        bitmap_offset = (bitmap_control >> 1) & 0x7F
        
        ctx = ParseContext.current()
        end = ctx.offset + (tag_length - 3)
        
        partial_virtual_bitmap = ""
        if ctx.offset < end:
            pvb_result = unpack(f"{end - ctx.offset}s")
            partial_virtual_bitmap = pvb_result
        
        return {
            "dtim_count": dtim_count,
            "dtim_period": dtim_period,
            "bitmap_control": {
                "raw": bitmap_control,
                "multicast": multicast,
                "bitmap_offset": bitmap_offset
            },
            "partial_virtual_bitmap": partial_virtual_bitmap
        }
    
    return unpack("<BBB", parser=_parser)

def country_code(tag_length: int, **kwargs) -> dict:
    def _parser(value: tuple, **kwargs) -> dict:
        country_str, environment = value
        country_str = country_str.decode(errors="ignore")

        ctx = ParseContext.current()
        end = ctx.offset + (tag_length - 4)

        sub_elements = {}
        i = 0
        while ctx.offset + 3 <= end:
            sub_result = unpack("<BBB", parser=lambda v, **k: {
                "first_channel": v[0],
                "num_channels": v[1],
                "max_tx_power": v[2]
            })
            sub_elements[i] = sub_result
            i += 1

        remaining = end - ctx.offset
        if remaining > 0:
            unpack(f"{remaining}s")

        result = {"country_code": country_str, "environment": environment}
        if sub_elements:
            result["sub_elements"] = sub_elements
        return result

    if tag_length < 4:
        return unpack("3sB", parser=lambda v, **k: {
            "country_code": v[0].decode(errors="ignore"),
            "environment": v[1]
        })

    return unpack("3sB", parser=_parser)

def erp_info(tag_length: int, **kwargs) -> dict:
    if tag_length < 1:
        return {}
    
    def _parser(value: int, **kwargs) -> dict:
        non_erp_present = bool(value & 0x01)
        use_protection = bool(value & 0x02)
        barker_preamble_mode = bool(value & 0x04)
        
        return {
            "non_erp_present": non_erp_present,
            "use_protection": use_protection,
            "barker_preamble_mode": barker_preamble_mode
        }
    
    return unpack("B", parser=_parser)

def ht_capabilities(tag_length: int, **kwargs) -> dict:
    if tag_length < 26:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        (ht_caps_info, ampdu_params, rx_mcs_bitmask, highest_supported_rate, 
                 tx_mcs_info, _reserved1, _reserved2, ht_ext_caps, 
                 txbf_caps, asel_caps, _pad) = values
        
        # HT Capabilities Info
        ldpc_coding_capable = bool(ht_caps_info & 0x0001)
        supported_channel_width = bool(ht_caps_info & 0x0002)
        sm_power_save = (ht_caps_info >> 2) & 0x03
        green_field = bool(ht_caps_info & 0x0010)
        short_gi_20mhz = bool(ht_caps_info & 0x0020)
        short_gi_40mhz = bool(ht_caps_info & 0x0040)
        tx_stbc = bool(ht_caps_info & 0x0080)
        rx_stbc = (ht_caps_info >> 8) & 0x03
        delayed_block_ack = bool(ht_caps_info & 0x0400)
        max_amsdu_length = bool(ht_caps_info & 0x0800)
        dsss_cck_40mhz = bool(ht_caps_info & 0x1000)
        forty_mhz_intolerant = bool(ht_caps_info & 0x4000)
        lsig_txop_protection = bool(ht_caps_info & 0x8000)
        
        # AMPDU Params
        max_rx_ampdu_length_exponent = ampdu_params & 0x03
        min_mpdu_start_spacing = (ampdu_params >> 2) & 0x07
        
        # TX MCS Info
        tx_mcs_set_defined = bool(tx_mcs_info & 0x01)
        tx_rx_mcs_set_equal = bool(tx_mcs_info & 0x02)
        max_tx_spatial_streams = (tx_mcs_info >> 2) & 0x03
        unequal_modulation = bool(tx_mcs_info & 0x10)
        
        # HT Extended Capabilities
        pco_support = bool(ht_ext_caps & 0x0001)
        pco_transition_time = (ht_ext_caps >> 1) & 0x03
        mcs_feedback = (ht_ext_caps >> 4) & 0x03
        htc_support = bool(ht_ext_caps & 0x0400)
        reverse_direction_responder = bool(ht_ext_caps & 0x0800)
        
        # TXBF Capabilities
        implicit_bf_rx = bool(txbf_caps & 0x00000001)
        rx_staggered_sounding = bool(txbf_caps & 0x00000002)
        tx_staggered_sounding = bool(txbf_caps & 0x00000004)
        rx_ndp = bool(txbf_caps & 0x00000008)
        tx_ndp = bool(txbf_caps & 0x00000010)
        
        # ASEL Capabilities
        asel_capable = bool(asel_caps & 0x01)
        explicit_csi_feedback_tx_asel = bool(asel_caps & 0x02)
        antenna_indices_feedback_tx_asel = bool(asel_caps & 0x04)
        explicit_csi_feedback = bool(asel_caps & 0x08)
        antenna_indices_feedback = bool(asel_caps & 0x10)
        rx_asel = bool(asel_caps & 0x20)
        
        return {
            "ht_caps_info": {
                "ldpc_coding_capable": ldpc_coding_capable,
                "supported_channel_width": supported_channel_width,
                "sm_power_save": sm_power_save,
                "green_field": green_field,
                "short_gi_20mhz": short_gi_20mhz,
                "short_gi_40mhz": short_gi_40mhz,
                "tx_stbc": tx_stbc,
                "rx_stbc": rx_stbc,
                "delayed_block_ack": delayed_block_ack,
                "max_amsdu_length": max_amsdu_length,
                "dsss_cck_40mhz": dsss_cck_40mhz,
                "forty_mhz_intolerant": forty_mhz_intolerant,
                "lsig_txop_protection": lsig_txop_protection
            },
            "ampdu_params": {
                "max_rx_ampdu_length_exponent": max_rx_ampdu_length_exponent,
                "min_mpdu_start_spacing": min_mpdu_start_spacing
            },
            "rx_mcs_bitmask": rx_mcs_bitmask,
            "highest_supported_rate": highest_supported_rate,
            "tx_mcs_info": {
                "tx_mcs_set_defined": tx_mcs_set_defined,
                "tx_rx_mcs_set_equal": tx_rx_mcs_set_equal,
                "max_tx_spatial_streams": max_tx_spatial_streams,
                "unequal_modulation": unequal_modulation
            },
            "ht_ext_caps": {
                "pco_support": pco_support,
                "pco_transition_time": pco_transition_time,
                "mcs_feedback": mcs_feedback,
                "htc_support": htc_support,
                "reverse_direction_responder": reverse_direction_responder
            },
            "txbf_caps": {
                "implicit_bf_rx": implicit_bf_rx,
                "rx_staggered_sounding": rx_staggered_sounding,
                "tx_staggered_sounding": tx_staggered_sounding,
                "rx_ndp": rx_ndp,
                "tx_ndp": tx_ndp
            },
            "asel_caps": {
                "asel_capable": asel_capable,
                "explicit_csi_feedback_tx_asel": explicit_csi_feedback_tx_asel,
                "antenna_indices_feedback_tx_asel": antenna_indices_feedback_tx_asel,
                "explicit_csi_feedback": explicit_csi_feedback,
                "antenna_indices_feedback": antenna_indices_feedback,
                "rx_asel": rx_asel
            }
        }
    
    fmt = "<HB10sHBBBHIBB" 
    return unpack(fmt, parser=_parser)

def rm_enable_capabilities(tag_length: int, **kwargs) -> dict:
    if tag_length < 2:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        byte0, byte1 = values
        
        byte0_parsed = {
            "link_measurement": bool(byte0 & 0x01),
            "neighbor_report": bool(byte0 & 0x02),
            "parallel_measurements": bool(byte0 & 0x04),
            "repeated_measurements": bool(byte0 & 0x08),
            "beacon_passive_measurement": bool(byte0 & 0x10),
            "beacon_active_measurement": bool(byte0 & 0x20),
            "beacon_table_measurement": bool(byte0 & 0x40),
            "beacon_measurement_reporting": bool(byte0 & 0x80)
        }
        
        byte1_parsed = {
            "frame_measurement": bool(byte1 & 0x01),
            "channel_load_measurement": bool(byte1 & 0x02),
            "noise_histogram_measurement": bool(byte1 & 0x04),
            "statistics_measurement": bool(byte1 & 0x08),
            "lci_measurement": bool(byte1 & 0x10),
            "lci_azimuth": bool(byte1 & 0x20),
            "tx_stream_category_measurement": bool(byte1 & 0x40),
            "triggered_tx_stream_measurement": bool(byte1 & 0x80)
        }
        
        return {
            "byte0": byte0_parsed,
            "byte1": byte1_parsed
        }
    
    return unpack("BB", parser=_parser)


def extended_capabilities(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    end = ctx.offset + tag_length
    
    def _parser_byte0(value: int, **kwargs) -> dict:
        bss_coexistence = bool(value & 0x01)
        extended_channel_switching = bool(value & 0x04)
        psmp_capability = bool(value & 0x10)
        
        return {
            "bss_coexistence": bss_coexistence,
            "extended_channel_switching": extended_channel_switching,
            "psmp_capability": psmp_capability
        }
    
    def _parser_byte2(value: int, **kwargs) -> dict:
        return {"bss_transition": bool(value & 0x08)}
    
    def _parser_byte3(value: int, **kwargs) -> dict:
        return {"interworking": bool(value & 0x80)}
    
    ext_caps = {}
    
    if tag_length >= 1:
        byte0 = unpack("B", parser=_parser_byte0)
        ext_caps["byte0"] = byte0
    
    if tag_length >= 2:
        unpack("B")  # Skip byte 1
    
    if tag_length >= 3:
        byte2 = unpack("B", parser=_parser_byte2)
        ext_caps["byte2"] = byte2
    
    if tag_length >= 4:
        byte3 = unpack("B", parser=_parser_byte3)
        ext_caps["byte3"] = byte3
    
    # Consume remaining bytes
    remaining = end - ctx.offset
    if remaining > 0:
        unpack(f"{remaining}s")
    
    return ext_caps


def qbss_load_element(tag_length: int, **kwargs) -> dict:
    if tag_length < 5:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        station_count, channel_utilization, available_admission_capacity = values
        
        return {
            "station_count": station_count,
            "channel_utilization": channel_utilization,
            "available_admission_capacity": available_admission_capacity
        }
    
    return unpack("<HBH", parser=_parser)


def power_constraint(tag_length: int, **kwargs) -> int:
    return unpack("B")


def tcp_report(tag_length: int, **kwargs) -> dict:
    def _parser(values: tuple, **kwargs) -> dict:
        tx_power, reserved = values
        
        return {
            "tx_power": tx_power,
            "reserved": reserved
        }
    
    return unpack("BB", parser=_parser)


def current_channel(tag_length: int, **kwargs) -> int:
    return unpack("B")


def rsn_information(tag_length: int, **kwargs) -> dict:
    if tag_length < 2:
        return {}
    
    ctx = ParseContext.current()
    end = ctx.offset + tag_length
    result = {}
    
    if ctx.offset + 2 <= end:
        result["version"] = unpack("<H")
    
    if ctx.offset + 4 <= end:
        def _group_parser(value: tuple, **kwargs):
            oui, ctype = value
            oui = bytes_for_oui(oui)
            return {
                **oui, 
                "cipher_type": ctype
            }
        result["group_cipher"] = unpack("3sB", parser=_group_parser)
    
    if ctx.offset + 2 <= end:
        def _pairwise_parser(pairwise_count: int, **kwargs):
            def __parser(value: tuple, **kwargs):
                oui, ctype = value
                oui = bytes_for_oui(oui)
                return {
                    **oui,
                    "cipher_type": ctype
                }
                
            pairwise_ciphers = {}
            for i in range(pairwise_count):
                if ctx.offset + OUI_LENGTH + 1 <= end:
                    pairwise_cipher_result = unpack("3sB", parser=__parser)
                    pairwise_ciphers[i] = pairwise_cipher_result
            return pairwise_ciphers
            
        result["pairwise_ciphers"] = unpack("<H", parser=_pairwise_parser)
    
    if ctx.offset + 2 <= end:
        def _akm_parser(akm_count: int, **kwargs):
            def __akm_item_parser(value: tuple, **kwargs):
                oui, a_type = value
                oui = bytes_for_oui(oui)
                return {
                    **oui,
                    "akm_type": a_type
                }
            
            akm_suites = {}
            for i in range(akm_count):
                if ctx.offset + 4 <= end:
                    akm_suite_result = unpack("3sB", parser=__akm_item_parser)
                    akm_suites[i] = akm_suite_result
            return akm_suites

        result["akm_suites"] = unpack("<H", parser=_akm_parser)
        if result["akm_suites"]:
            result["akm_suite_count"] = len(result["akm_suites"])

    if ctx.offset + 2 <= end:
        result["capabilities"] = unpack("<H", parser=_parse_rsn_capabilities)
    
    if ctx.offset + 2 <= end:
        def _pmkid_parser(pmkid_count: int, **kwargs):
            pmkids = {}
            for i in range(pmkid_count):
                if ctx.offset + EAPOL_PMKID_LENGTH <= end:
                    pmkid_result = unpack(f"{EAPOL_PMKID_LENGTH}s")
                    pmkids[i] = pmkid_result
            return pmkids

        result["pmkids"] = unpack("<H", parser=_pmkid_parser)
        if result["pmkids"]:
            result["pmkid_count"] = len(result["pmkids"])
            
    return result

def _parse_rsn_capabilities(value: int, **kwargs) -> dict:
    pre_auth = bool(value & 0x0001)
    no_pairwise = bool(value & 0x0002)
    ptksa_replay_counter = (value >> 2) & 0x03
    gtksa_replay_counter = (value >> 4) & 0x03
    mgmt_frame_protection_required = bool(value & 0x0040)
    mgmt_frame_protection_capable = bool(value & 0x0080)
    joint_multi_band_rsna = bool(value & 0x0100)
    peerkey_enabled = bool(value & 0x0200)
    spp_amsdu_capable = bool(value & 0x0400)
    spp_amsdu_required = bool(value & 0x0800)
    pbac = bool(value & 0x1000)
    extended_key_id = bool(value & 0x2000)
    ocvc = bool(value & 0x4000)
    reserved = bool(value & 0x8000)
    
    return {
        "pre_auth": pre_auth,
        "no_pairwise": no_pairwise,
        "ptksa_replay_counter": ptksa_replay_counter,
        "gtksa_replay_counter": gtksa_replay_counter,
        "mgmt_frame_protection_required": mgmt_frame_protection_required,
        "mgmt_frame_protection_capable": mgmt_frame_protection_capable,
        "joint_multi_band_rsna": joint_multi_band_rsna,
        "peerkey_enabled": peerkey_enabled,
        "spp_amsdu_capable": spp_amsdu_capable,
        "spp_amsdu_required": spp_amsdu_required,
        "pbac": pbac,
        "extended_key_id": extended_key_id,
        "ocvc": ocvc,
        "reserved": reserved
    }

def _get_extension_name(ext_id: int) -> str:
    extensions = {
        35: "HE Capabilities",
        36: "HE Operation",
        39: "UORA Parameter Set",
        59: "Short Beacon Interval",
        108: "EHT Capabilities" # Wi-Fi 7
    }
    return extensions.get(ext_id)

def tag_extended_he(tag_length: int, **kwargs) -> dict:
    def _parser(value: tuple, **kwargs):
        ext_tag_id, data = value
        logger.debug(f"_parser tag_extended_he\n{value}")
        return {
            "extension_id": ext_tag_id,
            "extension_name": _get_extension_name(ext_tag_id),
            "data": data
        }

    if tag_length < 2:
        return {}
    
    return unpack(f"B{tag_length -1}s", parser=_parser)
    
IE_DISPATCH = {
    TAG_SSID: {
        "name": "ssid",
        "description": "SSID",
        "parser": ssid
    },
    TAG_SUPPORTED_RATES: {
        "name": "supported_rates",
        "description": "Supported Rates",
        "parser": rates
    },
    TAG_CURRENT_CHANNEL: {
        "name": "current_channel",
        "description": "Current Channel",
        "parser": current_channel
    },
    TAG_TIM: {
        "name": "tim",
        "description": "Traffic Indication Map",
        "parser": tim_info
    },
    TAG_COUNTRY: {
        "name": "country",
        "description": "Country",
        "parser": country_code
    },
    TAG_QBSS_LOAD: {
        "name": "qbss_load",
        "description": "QBSS Load Element",
        "parser": qbss_load_element
    },
    TAG_POWER_CONSTRAINT: {
        "name": "power_constraint",
        "description": "Power Constraint",
        "parser": power_constraint
    },
    TAG_TPC_REPORT: {
        "name": "tpc_report",
        "description": "TPC Report",
        "parser": tcp_report
    },
    TAG_ERP: {
        "name": "erp_information",
        "description": "ERP Information",
        "parser": erp_info
    },
    TAG_EXTENDED_SUPPORTED_RATES: {
        "name": "extended_supported_rates",
        "description": "Extended Supported Rates",
        "parser": rates
    },
    TAG_VENDOR_SPECIFIC: {
        "name": "vendor_specific",
        "description": "Vendor Specific",
        "parser": vendor_specific
    },
    TAG_HT_CAPABILITIES: {
        "name": "ht_capabilities",
        "description": "HT Capabilities",
        "parser": ht_capabilities
    },
    TAG_RM_ENABLED_CAPABILITIES: {
        "name": "rm_enabled_capabilities",
        "description": "RM Enabled Capabilities",
        "parser": rm_enable_capabilities
    },
    TAG_RSN_INFORMATION: {
        "name": "rsn_information",
        "description": "RSN Information",
        "parser": rsn_information
    },
    TAG_EXTENDED_CAPABILITIES: {
        "name": "extended_capabilities",
        "description": "Extended Capabilities",
        "parser": extended_capabilities
    },
    TAG_EXTENDED_HE: {
        "name": "tag_extended_he",
        "description": "(Wifi 6) High Efficiency (HE)",
        "parser": tag_extended_he
    }
}

def ie_dispatch(value: tuple, **kwargs) -> dict:
    def _fallback(tag_length: int, **k):
        return unpack(f"{tag_length}s")

    ie_result = {}
    tag_number, tag_length = value

    ctx = ParseContext.current()
    start_offset = ctx.offset
    expected_end = start_offset + tag_length

    try:
        entry = IE_DISPATCH.get(tag_number, {})
        ie_result = {
            "tag_number": tag_number,
            "tag_length": tag_length,
            "name": entry.get("name"),
            "description": entry.get("description")
        }
        ie_result["data"] = run_dispatch(
            IE_DISPATCH,
            tag_number,
            fallback=_fallback,
            tag_length=tag_length
        )

    except Exception as e:
        logger.debug(f"IE parser error for tag {tag_number} value={value} entry={entry} : {e}")

    finally:
        if ctx.offset != expected_end:
            logger.debug(
                f"IE tag {tag_number} offset drift: expected={expected_end} got={ctx.offset} "
                f"(drift={ctx.offset - expected_end:+d})"
            )
            ctx.offset = min(expected_end, len(ctx.frame))

    return ie_result
