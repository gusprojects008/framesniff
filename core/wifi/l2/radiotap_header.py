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

    @classmethod
    def parse(cls, frame: bytes) -> (dict, int):
        def _parse_simple(name, value):
            return {name: value[0]}
        def _parse_signed(name, value):
            return {name: value[0]}
        def _parse_flags(name, value):
            FLAGS_FIELDS = [
                'cfp', 'preamble', 'wep', 'fragmentation',
                'fcs_at_end', 'data_pad', 'bad_fcs', 'short_gi'
            ]
            return {'flags': bitmap_value_for_dict(value[0], FLAGS_FIELDS)}
        def _parse_rate(name, value):
            return {'rate_mbps': value[0] * 0.5}
        def _parse_channel(name, value):
            freq, flags_val = value
            FLAGS_FIELDS = [
                None, None, None, None, 'turbo', 'cck', 'ofdm', '2ghz',
                '5ghz', 'passive', 'dynamic_cck_ofdm', 'gfsk', 'gsm',
                'static_turbo', 'half_rate', 'quarter_rate'
            ]
            return {
                'channel_freq': freq,
                'channel_flags': bitmap_value_for_dict(flags_val, FLAGS_FIELDS)
            }
        def _parse_rx_flags(name, value):
            FLAGS_FIELDS = [
                'bad_plcp', 'short_gi', # 0, 1
                None, # 2 (HT)
                'greenfield', # 3 (HT)
                'ht40', # 4 (HT)
                None, None, # 5, 6 (HT)
                'vht_ldpc_extra_symbol', # 7 (VHT)
                'vht_stbc', # 8 (VHT)
                'vht_txop_ps_not_allowed', # 9 (VHT)
                'vht_sgi_nsym_da' # 10 (VHT)
            ]
            return {'rx_flags': bitmap_value_for_dict(value[0], FLAGS_FIELDS)}
        def _parse_mcs(name, value):
            known, flags_val, mcs_index = value
            KNOWN_FIELDS = [
                'bandwidth', 'mcs_index', 'guard_interval', 'ht_format',
                'fec_type', 'stbc_streams', 'ness', 'ness_bit_1'
            ]
            FLAGS_FIELDS = ['bandwidth', None, 'guard_interval', 'ht_format', 'fec_type']
            return {
                'mcs': {
                    'known': bitmap_value_for_dict(known, KNOWN_FIELDS),
                    'flags': bitmap_value_for_dict(flags_val, FLAGS_FIELDS),
                    'index': mcs_index
                }
            }
        def _parse_ampdu_status(name, value):
            ref_num, flags_val, delim_crc, reserved = value
            FLAGS_FIELDS = [
                'report_zerolen', 'is_zerolen', 'last_known', 'is_last',
                'delim_crc_err', 'delim_crc_known'
            ]
            return {
                'ampdu_status': {
                    'reference_num': ref_num,
                    'flags': bitmap_value_for_dict(flags_val, FLAGS_FIELDS),
                    'delimiter_crc_value': delim_crc,
                    'reserved': reserved
                }
            }
        def _parse_vht(name, value):
            known, flags_val, bandwidth, mcs_nss1, mcs_nss2, mcs_nss3, mcs_nss4, coding, group_id, partial_aid = value
            KNOWN_FIELDS = [
                'stbc', 'txop_ps_not_allowed', 'guard_interval', 'sgi_nsym_da',
                'ldpc_extra_symbol', 'beamformed', 'bandwidth', 'group_id', 'partial_aid'
            ]
            return {
                'vht': {
                    'known': bitmap_value_for_dict(known, KNOWN_FIELDS),
                    'flags_is_stbc': bool(flags_val & 0x01),
                    'flags_txop_ps_not_allowed': bool(flags_val & 0x02),
                    'bandwidth': bandwidth,
                    'mcs_nss': [mcs_nss1, mcs_nss2, mcs_nss3, mcs_nss4],
                    'coding': coding,
                    'group_id': group_id,
                    'partial_aid': partial_aid
                }
            }

        RADIOTAP_FIELDS = [
            (0, "tsft", "<Q", 8, _parse_simple),
            (1, "flags", "<B", 1, _parse_flags),
            (2, "rate", "<B", 1, _parse_rate),
            (3, "channel", "<HH", 2, _parse_channel),
            (4, "fhss", "<BB", 1, lambda n, v: {"fhss": {'hop_set': v[0], 'hop_pattern': v[1]}}),
            (5, "dbm_antenna_signal", "<b", 1, _parse_signed),
            (6, "dbm_antenna_noise", "<b", 1, _parse_signed),
            (7, "lock_quality", "<H", 2, _parse_simple),
            (8, "tx_attenuation", "<H", 2, _parse_simple),
            (9, "db_tx_attenuation", "<H", 2, _parse_simple),
            (10, "dbm_tx_power", "<b", 1, _parse_signed),
            (11, "antenna", "<B", 1, _parse_simple),
            (12, "db_antenna_signal", "<B", 1, _parse_simple),
            (13, "db_antenna_noise", "<B", 1, _parse_simple),
            (14, "rx_flags", "<H", 2, _parse_rx_flags),
            (15, "tx_flags", "<H", 2, _parse_simple),
            (16, "rts_retries", "<B", 1, _parse_simple),
            (17, "data_retries", "<B", 1, _parse_simple),
            (19, "mcs", "<BBB", 1, _parse_mcs),
            (20, "ampdu_status", "<IHBB", 4, _parse_ampdu_status),
            (21, "vht", "<HBBBBBBHH", 2, _parse_vht)
        ]

        radiotap_info = {}
        offset = 0
        rth_length = 0

        try:
            unpacked, offset = safe_unpack("<BBH", frame, offset)
            if unpacked is None:
                return {"error": "Frame too short for Radiotap header"}, 0
            rth_version, rth_pad, rth_length = unpacked

            radiotap_info.update({"version": rth_version, "length": rth_length})

            if rth_length > len(frame):
                return {"error": "Radiotap length exceeds frame size"}, rth_length

            present_flags_all = []
            combined_present = 0
            i = 0
            while True:
                unpacked, offset = safe_unpack("<I", frame, offset)
                if unpacked is None:
                    return {"error": "Frame truncated before presence bitmap"}, rth_length
                
                present = unpacked[0]
                present_flags_all.append(present)
                combined_present |= (present << (32 * i))
                i += 1
                
                if not (present & (1 << 31)):
                    break
            
            radiotap_info["present_bitmaps"] = [hex(p) for p in present_flags_all]

            for bit_index, name, fmt, alignment, parser_func in RADIOTAP_FIELDS:
                if not (combined_present & (1 << bit_index)):
                    continue
                
                align_diff = (alignment - (offset % alignment)) % alignment
                offset += align_diff
                
                unpacked, new_offset = safe_unpack(fmt, frame, offset)
                if unpacked is None:
                    radiotap_info.setdefault("error", []).append(f"Not enough bytes for field '{name}'")
                    break
                
                parsed_data = parser_func(name, unpacked)
                radiotap_info.update(parsed_data)
                offset = new_offset

        except struct.error as e:
            radiotap_info.setdefault("error", []).append(f"Radiotap header struct error: {e}")

        return radiotap_info, rth_length
