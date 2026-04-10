import struct
from core.common.parser_utils import (bitmap_dict_to_hex, bitmap_value_for_dict, unpack)

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
def parse(cls, frame: bytes, offset: int = 0) -> (dict, int):
    start_offset = offset
    radiotap_info = {}
    rth_length = 0

    def _flags(value):
        return {'flags': bitmap_value_for_dict(value, [
            'cfp', 'preamble', 'wep', 'fragmentation',
            'fcs_at_end', 'data_pad', 'bad_fcs', 'short_gi'
        ])}

    def _channel(value):
        freq, flags_val = value
        return {
            'channel_freq': freq,
            'channel': freq_to_channel(freq),
            'channel_flags': bitmap_value_for_dict(flags_val, [
                None, None, None, None, 'turbo', 'cck', 'ofdm', '2ghz',
                '5ghz', 'passive', 'dynamic_cck_ofdm', 'gfsk', 'gsm',
                'static_turbo', 'half_rate', 'quarter_rate'
            ])
        }

    def _rx_flags(value):
        return {'rx_flags': bitmap_value_for_dict(value, [
            'bad_plcp', 'short_gi', None, 'greenfield', 'ht40', None, None,
            'vht_ldpc_extra_symbol', 'vht_stbc', 'vht_txop_ps_not_allowed',
            'vht_sgi_nsym_da'
        ])}

    def _mcs(value):
        known, flags_val, mcs_index = value
        return {'mcs': {
            'known': bitmap_value_for_dict(known, [
                'bandwidth', 'mcs_index', 'guard_interval', 'ht_format',
                'fec_type', 'stbc_streams', 'ness', 'ness_bit_1'
            ]),
            'flags': bitmap_value_for_dict(flags_val, [
                'bandwidth', None, 'guard_interval', 'ht_format', 'fec_type'
            ]),
            'index': mcs_index
        }}

    def _ampdu(value):
        ref_num, flags_val, delim_crc, reserved = value
        return {'ampdu_status': {
            'reference_num': ref_num,
            'flags': bitmap_value_for_dict(flags_val, [
                'report_zerolen', 'is_zerolen', 'last_known', 'is_last',
                'delim_crc_err', 'delim_crc_known'
            ]),
            'delimiter_crc_value': delim_crc,
            'reserved': reserved
        }}

    def _vht(value):
        known, flags_val, bandwidth, mcs_nss1, mcs_nss2, mcs_nss3, mcs_nss4, \
            coding, group_id, partial_aid = value
        return {'vht': {
            'known': bitmap_value_for_dict(known, [
                'stbc', 'txop_ps_not_allowed', 'guard_interval', 'sgi_nsym_da',
                'ldpc_extra_symbol', 'beamformed', 'bandwidth', 'group_id',
                'partial_aid'
            ]),
            'flags_is_stbc':              bool(flags_val & 0x01),
            'flags_txop_ps_not_allowed':  bool(flags_val & 0x02),
            'bandwidth':   bandwidth,
            'mcs_nss':     [mcs_nss1, mcs_nss2, mcs_nss3, mcs_nss4],
            'coding':      coding,
            'group_id':    group_id,
            'partial_aid': partial_aid
        }}

    RADIOTAP_FIELDS = [
        (0,  "tsft",              "<Q",          8, None),
        (1,  "flags",             "<B",          1, _flags),
        (2,  "rate",              "<B",          1, lambda v: {"rate_mbps": v * 0.5}),
        (3,  "channel",           "<HH",         2, _channel),
        (4,  "fhss",              "<BB",         1, lambda v: {"fhss": {"hop_set": v[0], "hop_pattern": v[1]}}),
        (5,  "dbm_antenna_signal","<b",          1, None),
        (6,  "dbm_antenna_noise", "<b",          1, None),
        (7,  "lock_quality",      "<H",          2, None),
        (8,  "tx_attenuation",    "<H",          2, None),
        (9,  "db_tx_attenuation", "<H",          2, None),
        (10, "dbm_tx_power",      "<b",          1, None),
        (11, "antenna",           "<B",          1, None),
        (12, "db_antenna_signal", "<B",          1, None),
        (13, "db_antenna_noise",  "<B",          1, None),
        (14, "rx_flags",          "<H",          2, _rx_flags),
        (15, "tx_flags",          "<H",          2, None),
        (16, "rts_retries",       "<B",          1, None),
        (17, "data_retries",      "<B",          1, None),
        (19, "mcs",               "<BBB",        1, _mcs),
        (20, "ampdu_status",      "<IHBB",       4, _ampdu),
        (21, "vht",               "<HBBBBBBBBH", 2, _vht),
    ]

    try:
        result, offset = unpack("<BBH", frame, offset)
        rth_version, rth_pad, rth_length = result["value"]

        radiotap_info.update({
            "version": rth_version,
            "pad":     rth_pad,
            "length":  rth_length,
        })

        if rth_length > len(frame):
            return {"error": "Radiotap length exceeds frame size"}, rth_length

        present_flags_all = {}
        combined_present  = 0

        for i in range(32):
            result, offset = unpack("<I", frame, offset)
            present = result["value"]

            present_flags_all[i] = hex(present)
            combined_present |= present << (32 * i)

            if not (present & (1 << 31)):
                break

        radiotap_info["present_bitmaps"] = present_flags_all

        for bit_index, name, fmt, alignment, parser_func in RADIOTAP_FIELDS:
            if not (combined_present & (1 << bit_index)):
                continue

            offset += (alignment - (offset % alignment)) % alignment

            result, offset = unpack(fmt, frame, offset)
            value = result["value"]

            if parser_func is None:
                radiotap_info[name] = value
            else:
                radiotap_info.update(parser_func(value))

    except Exception as e:
        logger.debug(f"Parser radiotap header error: {e}")

    return radiotap_info, rth_length
