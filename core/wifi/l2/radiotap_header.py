import struct
from ...common.useful_functions import (bitmap_dict_to_hex, bitmap_value_for_dict, safe_unpack)

class RadiotapHeader:
    @staticmethod
    def build():
        config = {
            "tsft": True,
            "flags": True,
            "rate": True,
            "channel": False,
            "antenna_signal": True,
            "mac_timestamp": 0,
            "data_rate": 5,
            "antenna_signal_dbm": -60,
        }

        rth_version = struct.pack("<B", 0)
        rth_pad = struct.pack("<B", 0)
        
        rth_btm_present = {
            "tsft": config["tsft"],
            "flags": config["flags"],
            "rate": config["rate"],
            "channel": config["channel"],
            "antenna_signal": config["antenna_signal"],
        }
        rth_btm_present_int = struct.pack("<I", RadiotapHeader.boolean_fields_to_hex(rth_btm_present))
        
        rth_mac_timestamp = struct.pack("<Q", config["mac_timestamp"])
        rth_btm_flags = {k: False for k in ["cfp", "preamble", "wep", "fragmentation", "fcs", "data_pad", "bad_fcs", "short_gi"]}
        rth_btm_flags_int = struct.pack("<B", RadiotapHeader.boolean_fields_to_hex(rth_btm_flags))
        rth_data_rate = struct.pack("<B", config["data_rate"])
        rth_btm_channels = {"2ghz": True, "5ghz": True}
        rth_btm_channels_int = struct.pack("<H", RadiotapHeader.boolean_fields_to_hex(rth_btm_channels))
        rth_antenna_signal = struct.pack("<b", config["antenna_signal_dbm"])

        radiotap_data = rth_mac_timestamp + rth_btm_flags_int + rth_data_rate + rth_btm_channels_int + rth_antenna_signal
        rth_length = struct.pack("<H", len(rth_version) + len(rth_pad) + len(rth_btm_present_int) + len(radiotap_data))
        
        return rth_version + rth_pad + rth_length + rth_btm_present_int + radiotap_data

    @staticmethod
    def parse(frame: bytes) -> (dict, int):
        def align_offset(offset, alignment):
            return (offset + (alignment - 1)) & ~(alignment - 1)
    
        radiotap_info = {}
        offset = 0
        rth_length = 0
    
        try:
            unpacked, offset = safe_unpack("<BBHI", frame, offset)
            if unpacked is None:
                return {"error": "Frame too short for Radiotap header"}, offset
            rth_version, rth_pad, rth_length, rth_present = unpacked
    
            field_names = [
                "tsft", "flags", "rate", "channel", "fhss", "dbm_antenna_signal",
                "dbm_antenna_noise", "lock_quality", "tx_attenuation", "db_tx_attenuation",
                "dbm_tx_power", "antenna", "db_antenna_signal", "db_antenna_noise",
                "rx_flags", "tx_flags", "rts_retries", "data_retries", "xchannel", "mcs",
                "ampdu_status", "vht", "frame_timestamp", "he", "he_mu", "he_mu_other_user",
                "zero_length_psdu_type", "lsig", "tlv", "radiotap_ns_next", "vendor_ns_next",
                "ext", "radiotap_ns_reserved", "vendor_ns_reserved", "ppdu", "ppdu_status",
                "ppdu_flags", "ppdu_data", "ru_allocation", "eht", "eht_mu", "eht_trig",
                "eht_mu_other_user", "zero_length_psdu", "zero_length_psdu_type_ext",
                "multi_user_info", "rx_info", "common_usable", "vendor_ext",
                "multi_user_ru_allocation", "multi_user_he_ltf", "multi_user_he_sig_a",
                "multi_user_he_sig_b", "multi_user_he_trig", "multi_user_eht_ru",
                "multi_user_eht_sig", "multi_user_eht_trig", "multi_user_eht_mu_other",
                "ext_reserved"
            ]
    
            present_flags = bitmap_value_for_dict(rth_present, field_names)
            radiotap_info.update({
                "version": rth_version,
                "pad": rth_pad,
                "length": rth_length,
                "present_flags": present_flags
            })
    
            field_sizes = {
                "tsft": 8, "flags": 1, "rate": 1, "channel": 4, "fhss": 2,
                "dbm_antenna_signal": 1, "dbm_antenna_noise": 1, "lock_quality": 2,
                "tx_attenuation": 2, "db_tx_attenuation": 2, "dbm_tx_power": 1,
                "antenna": 1, "db_antenna_signal": 1, "db_antenna_noise": 1,
                "rx_flags": 2, "tx_flags": 2, "rts_retries": 1, "data_retries": 1,
                "xchannel": 8, "mcs": 3, "ampdu_status": 8, "vht": 12,
                "frame_timestamp": 8, "he": 12, "he_mu": 12, "he_mu_other_user": 12,
                "zero_length_psdu_type": 1, "lsig": 4, "tlv": 0, "radiotap_ns_next": 0,
                "vendor_ns_next": 0, "ext": 0
            }
    
            for field, active in present_flags.items():
                if not active or field not in field_sizes:
                    continue
    
                size = field_sizes[field]
                if size == 0:
                    continue
                if offset + size > len(frame):
                    radiotap_info.setdefault("error", []).append(f"Not enough bytes for field {field}")
                    continue
                if size > 1:
                    offset = align_offset(offset, size)
    
                try:
                    if field == "channel":
                        unpacked, offset = safe_unpack("<HH", frame, offset)
                        if unpacked:
                            freq, flags = unpacked
                            radiotap_info["channel_freq"] = freq
                            radiotap_info["channel_flags"] = flags
                            radiotap_info["is_2ghz"] = bool(flags & 0x0080)
                            radiotap_info["is_5ghz"] = bool(flags & 0x0100)
                            bit_names = [
                                "700MHz", "800MHz", "900MHz", "Turbo", "CCK", "OFDM", 
                                "2GHz", "5GHz", "Passive", "Dynamic_CCK_OFDM", "GFSK", 
                                "GSM900", "Static_Turbo", "HalfRate", "QuarterRate"
                            ]
                            radiotap_info["channel_flags_bits"] = bitmap_value_for_dict(flags, bit_names)
                    elif field == "flags":
                        unpacked, offset = safe_unpack("<B", frame, offset)
                        if unpacked:
                            radiotap_info["flags"] = unpacked[0]
                            flag_bits = [
                                "cfp", "preamble", "wep", "fragmentation",
                                "fcs", "data_pad", "bad_fcs", "short_gi"
                            ]
                            radiotap_info["flags_bits"] = bitmap_value_for_dict(unpacked[0], flag_bits)
                    elif field == "rate":
                        unpacked, offset = safe_unpack("<B", frame, offset)
                        if unpacked:
                            radiotap_info[field] = unpacked[0] / 2.0
                    elif size == 1:
                        fmt = "<b" if field.startswith(("dbm_", "db_")) else "<B"
                        unpacked, offset = safe_unpack(fmt, frame, offset)
                        if unpacked:
                            radiotap_info[field] = unpacked[0]
                    elif size == 2:
                        unpacked, offset = safe_unpack("<H", frame, offset)
                        if unpacked:
                            radiotap_info[field] = unpacked[0]
                    elif size == 4:
                        unpacked, offset = safe_unpack("<I", frame, offset)
                        if unpacked:
                            radiotap_info[field] = unpacked[0]
                    elif size == 8:
                        unpacked, offset = safe_unpack("<Q", frame, offset)
                        if unpacked:
                            radiotap_info[field] = unpacked[0]
    
                except struct.error as e:
                    radiotap_info.setdefault("error", []).append(f"{field} unpack error: {e}")
    
        except struct.error as e:
            radiotap_info.setdefault("error", []).append(f"Radiotap header error: {e}")
    
        return radiotap_info, rth_length
