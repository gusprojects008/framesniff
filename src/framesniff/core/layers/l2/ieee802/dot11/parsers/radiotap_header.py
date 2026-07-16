from logging import getLogger
from core.common.parser import (
    ParseContext, unpack, bitmap_value_for_dict, freq_to_channel, fail
)

logger = getLogger(__name__)

def _parse_flags(value):
    return {'flags': bitmap_value_for_dict(value, [
        'cfp', 'preamble', 'wep', 'fragmentation',
        'fcs_at_end', 'data_pad', 'bad_fcs', 'short_gi'
    ])}

def _parse_channel(value):
    freq, flags_val = value
    channel_flags = bitmap_value_for_dict(flags_val, [
        None, None, None, None,           # bits 0-3 reserved
        'turbo', 'cck', 'ofdm', '2ghz',
        '5ghz', 'passive', 'dynamic_cck_ofdm', 'gfsk',
        'gsm', 'static_turbo', 'half_rate', 'quarter_rate'
    ])
    return {
        'channel_freq': freq,
        'channel': freq_to_channel(freq),
        'channel_flags': channel_flags
    }

def _parse_fhss(value):
    hop_set, hop_pattern = value
    return {'fhss': {'hop_set': hop_set, 'hop_pattern': hop_pattern}}

def _parse_rx_flags(value):
    return {'rx_flags': bitmap_value_for_dict(value, [
        'bad_plcp', None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None
        # rx_flags: only bit 1 (bad_plcp) defined by spec; rest reserved
        # keeping as full 16-bit map for forward compatibility
    ])}

def _parse_tx_flags(value):
    return {'tx_flags': bitmap_value_for_dict(value, [
        'fail', 'cts', 'rts', 'no_ack', 'no_seq', None, None, None,
        None, None, None, None, None, None, None, None
    ])}

def _parse_mcs(value):
    known, flags_val, mcs_index = value
    known_bits = bitmap_value_for_dict(known, [
        'bandwidth', 'mcs_index', 'guard_interval', 'ht_format',
        'fec_type', 'stbc_streams', 'ness', 'ness_bit_1'
    ])
    flags_bits = bitmap_value_for_dict(flags_val, [
        'bandwidth_0', 'bandwidth_1', 'guard_interval', 'ht_format',
        'fec_type', 'stbc_stream_0', 'stbc_stream_1', 'ness_bit_0'
    ])
    bw_map = {0: 20, 1: 40, 2: '20L', 3: '20U'}
    raw_bw = flags_val & 0x03
    return {'mcs': {
        'known': known_bits,
        'flags': flags_bits,
        'index': mcs_index,
        'bandwidth_mhz': bw_map.get(raw_bw) if known_bits.get('bandwidth') else None,
        'guard_interval_ns': 400 if (flags_val & 0x04) else 800,
        'ht_format': 'greenfield' if (flags_val & 0x08) else 'mixed',
        'fec': 'ldpc' if (flags_val & 0x10) else 'bcc',
        'stbc_streams': (flags_val >> 5) & 0x03,
    }}

def _parse_ampdu_status(value):
    ref_num, flags_val, delim_crc, reserved = value
    flags_bits = bitmap_value_for_dict(flags_val, [
        'report_zerolen', 'is_zerolen', 'last_known', 'is_last',
        'delim_crc_err', 'delim_crc_known', None, None,
        None, None, None, None, None, None, None, None
    ])
    return {'ampdu_status': {
        'reference_num': ref_num,
        'flags': flags_bits,
        'delimiter_crc_value': delim_crc,
        'reserved': reserved
    }}

def _parse_vht(value):
    (known, flags_val, bandwidth,
     mcs_nss1, mcs_nss2, mcs_nss3, mcs_nss4,
     coding, group_id, partial_aid) = value

    known_bits = bitmap_value_for_dict(known, [
        'stbc', 'txop_ps_not_allowed', 'guard_interval', 'sgi_nsym_da',
        'ldpc_extra_symbol', 'beamformed', 'bandwidth', 'group_id', 'partial_aid',
        None, None, None, None, None, None, None
    ])

    def _decode_mcs_nss(raw):
        if raw == 0:
            return None
        return {'nss': raw & 0x0F, 'mcs': (raw >> 4) & 0x0F}

    coding_streams = [
        'ldpc' if (coding >> i) & 1 else 'bcc'
        for i in range(4)
    ]

    bw_map = {
        0: '20', 1: '40', 2: '80', 3: '80+80_or_160',
        4: '20L', 5: '20U', 6: '40L', 7: '40U',
        8: '80L', 9: '80U', 10: '80+80L', 11: '80+80U'
    }

    return {'vht': {
        'known': known_bits,
        'stbc': bool(flags_val & 0x01),
        'txop_ps_not_allowed': bool(flags_val & 0x02),
        'guard_interval': 'short' if (flags_val & 0x04) else 'long',
        'sgi_nsym_disambiguation': bool(flags_val & 0x08),
        'ldpc_extra_ofdm_symbol': bool(flags_val & 0x10),
        'beamformed': bool(flags_val & 0x20),
        'bandwidth': bw_map.get(bandwidth, f'unknown({bandwidth})'),
        'bandwidth_raw': bandwidth,
        'mcs_nss': [_decode_mcs_nss(x) for x in (mcs_nss1, mcs_nss2, mcs_nss3, mcs_nss4)],
        'coding': coding_streams,
        'group_id': group_id,
        'partial_aid': partial_aid,
    }}

def _parse_timestamp(value):
    ts_val, ts_accuracy, ts_unit_pos, ts_flags = value
    unit_map = {
        0: 'ms', 1: 'us', 2: 'ns', 3: '10ns',
        4: '100ns', 5: '500ns', 6: '1us', 7: '10us'
    }
    return {'timestamp': {
        'value': ts_val,
        'accuracy': ts_accuracy,
        'unit': unit_map.get(ts_unit_pos & 0x0F, f'unknown({ts_unit_pos & 0x0F})'),
        'sample_offset': (ts_unit_pos >> 4) & 0x0F,
        'flags': {
            'accuracy_known': bool(ts_flags & 0x01),
            'known': bool(ts_flags & 0x02),
        }
    }}

def _parse_he(value):
    return {'he': {i + 1: v for i, v in enumerate(value)}}

def _parse_he_mu(value):
    flags1, flags2, ru_ch1_0, ru_ch1_1, ru_ch1_2, ru_ch1_3, ru_ch2_0, ru_ch2_1, ru_ch2_2, ru_ch2_3 = value
    return {'he_mu': {
        'flags1': flags1, 'flags2': flags2,
        'ru_channel1': [ru_ch1_0, ru_ch1_1, ru_ch1_2, ru_ch1_3],
        'ru_channel2': [ru_ch2_0, ru_ch2_1, ru_ch2_2, ru_ch2_3],
    }}

RADIOTAP_FIELDS = [
    # bit  name                   fmt              align  parser
    (0,  "tsft",               "<Q",           8,  lambda v, **_: {"tsft": v}),
    (1,  "flags",              "<B",           1,  lambda v, **_: _parse_flags(v)),
    (2,  "rate",               "<B",           1,  lambda v, **_: {"rate_mbps": v * 0.5}),
    (3,  "channel",            "<HH",          2,  lambda v, **_: _parse_channel(v)),
    (4,  "fhss",               "<BB",          1,  lambda v, **_: _parse_fhss(v)),
    (5,  "dbm_antenna_signal", "<b",           1,  lambda v, **_: {"dbm_antenna_signal": v}),
    (6,  "dbm_antenna_noise",  "<b",           1,  lambda v, **_: {"dbm_antenna_noise": v}),
    (7,  "lock_quality",       "<H",           2,  lambda v, **_: {"lock_quality": v}),
    (8,  "tx_attenuation",     "<H",           2,  lambda v, **_: {"tx_attenuation": v}),
    (9,  "db_tx_attenuation",  "<H",           2,  lambda v, **_: {"db_tx_attenuation": v}),
    (10, "dbm_tx_power",       "<b",           1,  lambda v, **_: {"dbm_tx_power": v}),
    (11, "antenna",            "<B",           1,  lambda v, **_: {"antenna": v}),
    (12, "db_antenna_signal",  "<B",           1,  lambda v, **_: {"db_antenna_signal": v}),
    (13, "db_antenna_noise",   "<B",           1,  lambda v, **_: {"db_antenna_noise": v}),
    (14, "rx_flags",           "<H",           2,  lambda v, **_: _parse_rx_flags(v)),
    (15, "tx_flags",           "<H",           2,  lambda v, **_: _parse_tx_flags(v)),
    (16, "rts_retries",        "<B",           1,  lambda v, **_: {"rts_retries": v}),
    (17, "data_retries",       "<B",           1,  lambda v, **_: {"data_retries": v}),
    # bit 18: XChannel (obsolete Atheros extension, skip)
    (19, "mcs",                "<BBB",         1,  lambda v, **_: _parse_mcs(v)),
    (20, "ampdu_status",       "<IHBB",        4,  lambda v, **_: _parse_ampdu_status(v)),
    (21, "vht",                "<HBBBBBBBBxH", 2,  lambda v, **_: _parse_vht(v)),
    (22, "timestamp",          "<QHBB",        8,  lambda v, **_: _parse_timestamp(v)),
    # bits 23–28: HE, HE-MU, HE-MU other user, 0-length PSDU, L-SIG, TLV
    (23, "he",                 "<HHHHHH",      2,  lambda v, **_: _parse_he(v)),
    (24, "he_mu",              "<HHBBBBBBBB",  2,  lambda v, **_: _parse_he_mu(v)),
    # bits 25-28 omitted (rare / very new)
]

_FIELD_BY_BIT = {bit: (name, fmt, align, pfunc) for bit, name, fmt, align, pfunc in RADIOTAP_FIELDS}

def parser(**kwargs) -> dict:
    def _parser(value: tuple, **kwargs) -> dict:
        ctx = ParseContext.current()
        frame_len = len(ctx.frame)
        rth_version, rth_pad, rth_length = value

        result = {
            "version": rth_version,
            "pad": rth_pad,
            "length": rth_length,
        }

        if rth_version != 0 or rth_length > frame_len:
            logger.debug(f"Radiotap: invalid header ver={rth_version} len={rth_length} frame_len={frame_len}")
            return fail(result, rth_length, "Invalid radiotap header")

        present_bitmaps = {}
        combined_present = 0

        try:
            for word_index in range(32):
                present_data = unpack("<I", parser=lambda v, **kw: v)
                word_val = present_data["parsed"]
                present_bitmaps[word_index] = word_val

                combined_present |= (word_val & 0x7FFFFFFF)

                if not (word_val & (1 << 31)):
                    break

        except Exception as e:
            logger.debug(f"Radiotap: error reading present bitmaps: {e}")
            result["present_bitmaps"] = present_bitmaps
            return fail(result, rth_length, "Invalid radiotap header")

        result["present_bitmaps"] = present_bitmaps

        for bit_index in range(29):
            if not (combined_present & (1 << bit_index)):
                continue
            if bit_index not in _FIELD_BY_BIT:
                logger.debug(f"Radiotap: unknown bit {bit_index} at offset {ctx.offset}, stopping")
                break
              
            name, fmt, alignment, pfunc = _FIELD_BY_BIT[bit_index]

            try:
                if alignment > 1:
                    pad = (alignment - (ctx.offset % alignment)) % alignment
                    ctx.offset += pad

                field_result = unpack(fmt, parser=pfunc)

                if pfunc is None:
                    result[name] = field_result["value"]
                else:
                    result.update(field_result["parsed"])
            except Exception as e:
                logger.debug(
                    f"Radiotap: error parsing field bit={bit_index} name={name}: {e}"
                )
                break

        ctx.offset = min(rth_length, frame_len)
        return result

    result = {}

    try:
        result = unpack("<BBH", parser=_parser)
    except Exception as e:
        logger.debug(f"Parser radiotap header error: {e}")

    return result
