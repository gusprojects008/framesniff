from uuid import UUID
from logging import getLogger
from core.common.constants.ieee802_11 import *
from core.common.constants.l2 import *
from core.common.parser_utils import (unpack, ParseContext, run_dispatch, bytes_for_mac, add_metadata)

logger = getLogger(__name__)

MIN_IE_LEN = 2

# ============= TAG NUMBERS =============
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

# ============= OUI CONSTANTS =============
OUI_MICROSOFT = "00:50:f2"
OUI_IEEE_80211 = "00:0f:ac"
OUI_WFA = "50:6f:9a"
OUI_MEDIATEK = "00:0c:43"
OUI_BROADCOM = "00:10:18"
OUI_ATHEROS = "00:03:7f"

# ============= VENDOR TYPE CONSTANTS =============
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

# ============= WPS CONSTANTS =============
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
            oui = bytes_for_mac(attr_data[2:6])
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
    vendor_data_start = ctx.offset
    vendor_data_end = vendor_data_start + (tag_length - 4)  # 4 bytes OUI + type
    
    result = {}

    while ctx.offset + 4 <= vendor_data_end:
        attr_result = unpack(">HH")
        attr_type = attr_result["value"][0]
        attr_len = attr_result["value"][1]

        if ctx.offset + attr_len > vendor_data_end:
            logger.debug("WPS attribute truncated")
            break

        attr_data_result = unpack(f"{attr_len}s")
        attr_data = attr_data_result["value"].encode() if isinstance(attr_data_result["value"], str) else bytes.fromhex(attr_data_result["value"])

        parsed_attr = _parse_wps_attribute(attr_type, attr_data)
        result.update(parsed_attr)

    return result


def _wmm_wme_extension(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    vendor_data_start = ctx.offset
    vendor_data_end = vendor_data_start + (tag_length - 4)
    
    result = {}

    if ctx.offset + 4 > vendor_data_end:
        return result

    result["wme_subtype"] = unpack("B")["value"]
    result["wme_version"] = unpack("B")["value"]
    result["qos_info"] = unpack("B")["value"]
    result["reserved"] = unpack("B")["value"]

    ac_params = {}

    while ctx.offset + 4 <= vendor_data_end:
        aci_aifsn = unpack("B")["value"]
        ecw = unpack("B")["value"]
        txop = unpack("<H")["value"]

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


def _rsn_capabilities(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    
    rsn_caps_result = unpack(
        "<H",
        parser=lambda value: {
            "pre_auth": bool(value & 0x0001),
            "no_pairwise": bool(value & 0x0002),
            "ptksa_replay_counter": (value >> 2) & 0x03,
            "gtksa_replay_counter": (value >> 4) & 0x03,
            "mgmt_frame_protection_required": bool(value & 0x0040),
            "mgmt_frame_protection_capable": bool(value & 0x0080),
            "joint_multi_band_rsna": bool(value & 0x0100),
            "peerkey_enabled": bool(value & 0x0200),
            "spp_amsdu_capable": bool(value & 0x0400),
            "spp_amsdu_required": bool(value & 0x0800),
            "pbac": bool(value & 0x1000),
            "extended_key_id": bool(value & 0x2000),
            "ocvc": bool(value & 0x4000),
            "reserved": bool(value & 0x8000)
        }
    )
    
    return rsn_caps_result["parsed"]


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
        WFA_VENDOR_P2P: {"description": "Wi-Fi Alliance P2P", "parser": None}
        WFA_VENDOR_HS20: {"description": "Wi-Fi Alliance Hotspot 2.0", "parser": None}
        WFA_VENDOR_OSEN: {"description": "Wi-Fi Alliance OSEN", "parser": None}
    },
    OUI_MEDIATEK: {"description": "MediaTek Inc", "parser": None},
    OUI_BROADCOM: {"description": "Broadcom", "parser": None},
    OUI_ATHEROS: {"description": "Atheros", "parser": None}
}


def vendor_specific(tag_length: int, **kwargs) -> dict:
    def _parser(value: tuple, **kwargs) -> dict:
        oui, vtype = value
        result = {}
        result["oui"] = bytes_for_mac(oui)
        result["type"] = vtype
        result.update(
            run_dispatch(
                dispatch_table=SPECIFIC_VENDOR_DISPATCH,
                dispatch_id=vtype,
                fallback=lambda **k: unpack(f"{tag_length - 4}s"),
                tag_length=tag_length # Passado para os parsers internos
            )
        )
        post_process=lambda result, **k: result.update({
            "description": dispatch.get(vtype, {}).get("description", "Generic Vendor Specific"),
        }
        return result

    result = unpack("3sB", parser=_parser)]

    dispatch_table = {tid: entry["parser"] for tid, entry in oui_handlers.items() if entry.get("parser")}


def vendor_specific(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    end = ctx.offset + tag_length

    oui_result = unpack("3s", parser=lambda value: bytes_for_mac(value))
    oui = oui_result["parsed"]["mac"]

    vendor_type_result = unpack("B")
    vendor_type = vendor_type_result["value"]

    remaining = end - ctx.offset
    vendor_data_result = unpack(f"{remaining}s")
    vendor_data = vendor_data_result["value"]

    vendor_info = VENDOR_DESCRIPTION.get(oui, {})
    if isinstance(vendor_info, str):
        description = vendor_info
    else:
        description = vendor_info.get(vendor_type, "Generic Vendor Specific")

    result = {
        "oui": oui,
        "type": vendor_type,
        "description": description,
        "data": vendor_data
    }

    if oui in VENDOR_DISPATCH and vendor_type in VENDOR_DISPATCH[oui]:
        vendor_handler = VENDOR_DISPATCH[oui][vendor_type].get("parser")
        if vendor_handler:
            try:
                ctx.offset -= remaining
                parsed = vendor_handler["parser"](tag_length - 4, **kwargs)
                result["parsed"] = parsed
            except Exception as e:
                logger.debug(f"Vendor parser error for {oui}:{vendor_type}: {e}")

    return result

def ssid(tag_length: int, **kwargs) -> dict:
    """Parse SSID IE."""
    result = unpack(
        f"{tag_length}s",
        parser=lambda value: value.decode(errors="ignore")
    )
    return result["parsed"] if result["parsed"] else ""


def rates(tag_length: int, **kwargs) -> dict:
    """Parse Supported Rates IE."""
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
        result[i] = rate_result["parsed"]
        i += 1

    return result


def tim_info(tag_length: int, **kwargs) -> dict:
    """Parse TIM IE."""
    if tag_length < 4:
        return {}

    ctx = ParseContext.current()
    end = ctx.offset + tag_length

    tim = {}
    tim["dtim_count"] = unpack("B")["value"]
    tim["dtim_period"] = unpack("B")["value"]

    bitmap_control_result = unpack(
        "B",
        parser=lambda value: {
            "raw": value,
            "multicast": bool(value & 0x01),
            "bitmap_offset": (value >> 1) & 0x7F
        }
    )
    tim["bitmap_control"] = bitmap_control_result["parsed"]

    remaining = end - ctx.offset
    if remaining > 0:
        tim["partial_virtual_bitmap"] = unpack(f"{remaining}s")["value"]
    else:
        tim["partial_virtual_bitmap"] = ""

    return tim


def country_code(tag_length: int, **kwargs) -> dict:
    """Parse Country IE."""
    result = {}

    result["country_code"] = unpack(
        "3s",
        parser=lambda value: value.decode(errors="ignore")
    )["parsed"]

    ctx = ParseContext.current()
    end = ctx.offset + tag_length

    if tag_length > 3:
        result["environment"] = unpack("B")["value"]

    if tag_length > 4:
        sub_elements = {}
        i = 0
        while ctx.offset + 3 <= end:
            sub_elements[i] = {
                "first_channel": unpack("B")["value"],
                "num_channels": unpack("B")["value"],
                "max_tx_power": unpack("B")["value"]
            }
            i += 1
        result["sub_elements"] = sub_elements

    return result


def erp_info(tag_length: int, **kwargs) -> dict:
    """Parse ERP Information IE."""
    if tag_length < 1:
        return {}

    return unpack(
        "B",
        parser=lambda value: {
            "non_erp_present": bool(value & 0x01),
            "use_protection": bool(value & 0x02),
            "barker_preamble_mode": bool(value & 0x04)
        }
    )["parsed"]


def ht_capabilities(tag_length: int, **kwargs) -> dict:
    """Parse HT Capabilities IE."""
    if tag_length < 26:
        return {}

    ht = {}

    ht["ht_caps_info"] = unpack(
        "<H",
        parser=lambda value: {
            "ldpc_coding_capable": bool(value & 0x0001),
            "supported_channel_width": bool(value & 0x0002),
            "sm_power_save": (value >> 2) & 0x03,
            "green_field": bool(value & 0x0010),
            "short_gi_20mhz": bool(value & 0x0020),
            "short_gi_40mhz": bool(value & 0x0040),
            "tx_stbc": bool(value & 0x0080),
            "rx_stbc": (value >> 8) & 0x03,
            "delayed_block_ack": bool(value & 0x0400),
            "max_amsdu_length": bool(value & 0x0800),
            "dsss_cck_40mhz": bool(value & 0x1000),
            "forty_mhz_intolerant": bool(value & 0x4000),
            "lsig_txop_protection": bool(value & 0x8000)
        }
    )["parsed"]

    ht["ampdu_params"] = unpack(
        "B",
        parser=lambda value: {
            "max_rx_ampdu_length_exponent": value & 0x03,
            "min_mpdu_start_spacing": (value >> 2) & 0x07
        }
    )["parsed"]

    ht["rx_mcs_bitmask"] = unpack("10s")["value"]

    ht["highest_supported_rate"] = unpack("<H")["value"]

    ht["tx_mcs_info"] = unpack(
        "B",
        parser=lambda value: {
            "tx_mcs_set_defined": bool(value & 0x01),
            "tx_rx_mcs_set_equal": bool(value & 0x02),
            "max_tx_spatial_streams": (value >> 2) & 0x03,
            "unequal_modulation": bool(value & 0x10)
        }
    )["parsed"]

    unpack("3s")  # reserved

    ht["ht_ext_caps"] = unpack(
        "<H",
        parser=lambda value: {
            "pco_support": bool(value & 0x0001),
            "pco_transition_time": (value >> 1) & 0x03,
            "mcs_feedback": (value >> 4) & 0x03,
            "htc_support": bool(value & 0x0400),
            "reverse_direction_responder": bool(value & 0x0800)
        }
    )["parsed"]

    ht["txbf_caps"] = unpack(
        "<I",
        parser=lambda value: {
            "implicit_bf_rx": bool(value & 0x00000001),
            "rx_staggered_sounding": bool(value & 0x00000002),
            "tx_staggered_sounding": bool(value & 0x00000004),
            "rx_ndp": bool(value & 0x00000008),
            "tx_ndp": bool(value & 0x00000010)
        }
    )["parsed"]

    ht["asel_caps"] = unpack(
        "B",
        parser=lambda value: {
            "asel_capable": bool(value & 0x01),
            "explicit_csi_feedback_tx_asel": bool(value & 0x02),
            "antenna_indices_feedback_tx_asel": bool(value & 0x04),
            "explicit_csi_feedback": bool(value & 0x08),
            "antenna_indices_feedback": bool(value & 0x10),
            "rx_asel": bool(value & 0x20)
        }
    )["parsed"]

    return ht


def rm_enable_capabilities(tag_length: int, **kwargs) -> dict:
    """Parse RM Enabled Capabilities IE."""
    if tag_length < 2:
        return {}

    byte0 = unpack(
        "B",
        parser=lambda value: {
            "link_measurement": bool(value & 0x01),
            "neighbor_report": bool(value & 0x02),
            "parallel_measurements": bool(value & 0x04),
            "repeated_measurements": bool(value & 0x08),
            "beacon_passive_measurement": bool(value & 0x10),
            "beacon_active_measurement": bool(value & 0x20),
            "beacon_table_measurement": bool(value & 0x40),
            "beacon_measurement_reporting": bool(value & 0x80)
        }
    )["parsed"]

    byte1 = unpack(
        "B",
        parser=lambda value: {
            "frame_measurement": bool(value & 0x01),
            "channel_load_measurement": bool(value & 0x02),
            "noise_histogram_measurement": bool(value & 0x04),
            "statistics_measurement": bool(value & 0x08),
            "lci_measurement": bool(value & 0x10),
            "lci_azimuth": bool(value & 0x20),
            "tx_stream_category_measurement": bool(value & 0x40),
            "triggered_tx_stream_measurement": bool(value & 0x80)
        }
    )["parsed"]

    return {"byte0": byte0, "byte1": byte1}


def extended_capabilities(tag_length: int, **kwargs) -> dict:
    """Parse Extended Capabilities IE."""
    ext_caps = {}
    ctx = ParseContext.current()
    end = ctx.offset + tag_length

    if tag_length >= 1:
        byte0 = unpack(
            "B",
            parser=lambda value: {
                "bss_coexistence": bool(value & 0x01),
                "extended_channel_switching": bool(value & 0x04),
                "psmp_capability": bool(value & 0x10)
            }
        )["parsed"]
        ext_caps["byte0"] = byte0

    if tag_length >= 2:
        unpack("B")  # Skip byte 1

    if tag_length >= 3:
        byte2 = unpack(
            "B",
            parser=lambda value: {"bss_transition": bool(value & 0x08)}
        )["parsed"]
        ext_caps["byte2"] = byte2

    if tag_length >= 4:
        byte3 = unpack(
            "B",
            parser=lambda value: {"interworking": bool(value & 0x80)}
        )["parsed"]
        ext_caps["byte3"] = byte3

    remaining = end - ctx.offset
    if remaining > 0:
        unpack(f"{remaining}s")

    return ext_caps


def qbss_load_element(tag_length: int, **kwargs) -> dict:
    """Parse QBSS Load Element IE."""
    if tag_length < 5:
        return {}

    result = unpack(
        "<HBH",
        parser=lambda value: {
            "station_count": value[0],
            "channel_utilization": value[1],
            "available_admission_capacity": value[2]
        }
    )["parsed"]

    return result


def power_constraint(tag_length: int, **kwargs) -> dict:
    """Parse Power Constraint IE."""
    return unpack("B")["value"]


def tcp_report(tag_length: int, **kwargs) -> dict:
    """Parse TPC Report IE."""
    return unpack(
        "BB",
        parser=lambda value: {
            "tx_power": value[0],
            "reserved": value[1]
        }
    )["parsed"]


def current_channel(tag_length: int, **kwargs) -> dict:
    """Parse Current Channel IE."""
    return unpack("B")["value"]


def rsn_information(tag_length: int, **kwargs) -> dict:
    """Parse RSN Information IE."""
    result = {}

    if tag_length < 2:
        return result

    ctx = ParseContext.current()
    start = ctx.offset
    end = start + tag_length

    result["version"] = unpack("<H")["value"]

    if ctx.offset + 4 <= end:
        group_cipher = unpack(
            "3sB",
            parser=lambda value: {
                "oui": bytes_for_mac(value[0] if isinstance(value[0], bytes) else bytes.fromhex(value[0])),
                "cipher_type": value[1]
            }
        )["parsed"]
        result["group_cipher"] = group_cipher

    if ctx.offset + 2 <= end:
        pairwise_count_field = unpack("<H")
        count = pairwise_count_field["value"]
        result["pairwise_cipher_count"] = count
        pairwise = {}
        for i in range(count):
            if ctx.offset + 4 <= end:
                pairwise_result = unpack(
                    "3sB",
                    parser=lambda value: {
                        "oui": bytes_for_mac(value[0] if isinstance(value[0], bytes) else bytes.fromhex(value[0])),
                        "cipher_type": value[1]
                    }
                )
                pairwise[i] = pairwise_result["parsed"]
        if pairwise:
            result["pairwise_ciphers"] = pairwise

    if ctx.offset + 2 <= end:
        akm_count_field = unpack("<H")
        count = akm_count_field["value"]
        result["akm_suite_count"] = count
        akm = {}
        for i in range(count):
            if ctx.offset + 4 <= end:
                akm_result = unpack(
                    "3sB",
                    parser=lambda value: {
                        "oui": bytes_for_mac(value[0] if isinstance(value[0], bytes) else bytes.fromhex(value[0])),
                        "akm_type": value[1]
                    }
                )
                akm[i] = akm_result["parsed"]
        if akm:
            result["akm_suites"] = akm

    if ctx.offset + 2 <= end:
        result["capabilities"] = _rsn_capabilities(tag_length)

    if ctx.offset + 2 <= end:
        pmkid_count_field = unpack("<H")
        count = pmkid_count_field["value"]
        result["pmkid_count"] = count
        pmkids = {}
        for i in range(count):
            if ctx.offset + EAPOL_PMKID_LENGTH <= end:
                pmkid_result = unpack(f"{EAPOL_PMKID_LENGTH}s")
                pmkids[i] = pmkid_result["value"]
        if pmkids:
            result["pmkids"] = pmkids

    return result

# ============= IE DISPATCH TABLE =============
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
    }
}


def ie_dispatch(value: tuple, **kwargs) -> dict:
    return run_dispatch(IE_DISPATCH, tag_number, 
    tag_number, tag_length = value
    entry = IE_DISPATCH.get(tag_number, {})
    parser = entry.get("parser")
    description = entry.get("description", "Unknown IE")

    if not parser:
        ctx = ParseContext.current()
        remaining = ctx.offset + tag_length - ctx.offset
        unknown_result = unpack(f"{remaining}s")
        return {
            "tag_number": tag_number,
            "tag_length": tag_length,
            "tag_name": entry.get("name"),
            "description": description,
            "data": unknown_result["value"]
        }

    try:
        parsed_result = parser(tag_length=tag_length)
    except Exception as e:
        logger.debug(f"IE parser error for tag {tag_number}: {e}")
        parsed_result = None

    return {
        "tag_number": tag_number,
        "tag_length": tag_length,
        "tag_name": entry.get("name", f"unknown_{tag_number}"),
        "description": description,
        "parsed": parsed_result
    }
