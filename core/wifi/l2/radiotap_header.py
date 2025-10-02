import struct
from ...common.useful_functions import boolean_fields_to_hex

import struct

class RadiotapHeader:
    @staticmethod
    def build(**kwargs):
        config = {
            "tsft": True,
            "flags": True,
            "rate": True,
            "channel": False,
            "antenna_signal": True,
            "mac_timestamp": 0,
            "data_rate": 5,
            "antenna_signal_dbm": -60,
            **kwargs
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
    def parse(frame):
        def align_offset(offset, alignment):
            return (offset + (alignment - 1)) & ~(alignment - 1)

        radiotap_info = {}
        offset = 0
        
        if len(frame) < 8:
            return None, offset

        rth_version, rth_pad, rth_length, rth_present = struct.unpack_from("<BBHI", frame, offset)
        offset += struct.calcsize("<BBHI")

        it_present_fields = {
            "tsft": (0, 8),
            "flags": (1, 1),
            "rate": (2, 1),
            "channel": (3, 4),
            "fhss": (4, 2),
            "dbm_antenna_signal": (5, 1),
            "dbm_antenna_noise": (6, 1),
            "lock_quality": (7, 2),
            "tx_attenuation": (8, 2),
            "db_tx_attenuation": (9, 2),
            "dbm_tx_power": (10, 1),
            "antenna": (11, 1),
            "db_antenna_signal": (12, 1),
            "db_antenna_noise": (13, 1),
            "rx_flags": (14, 2),
            "tx_flags": (15, 2),
            "rts_retries": (16, 1),
            "data_retries": (17, 1),
            "xchannel": (18, 8),
            "mcs": (19, 3),
            "ampdu_status": (20, 8),
            "vht": (21, 12),
            "frame_timestamp": (22, 8),
            "he": (23, 12),
            "he_mu": (24, 12),
            "he_mu_other_user": (25, 12),
            "zero_length_psdu_type": (26, 1),
            "lsig": (27, 4),
            "tlv": (28, 0),
            "radiotap_ns_next": (29, 0),
            "vendor_ns_next": (30, 0),
            "ext": (31, 4)
        }

        it_presents = [rth_present]
        while it_presents[-1] & (1 << it_present_fields["ext"][0]):
            if offset + 4 > len(frame):
                break
            it_presents.append(struct.unpack_from("<I", frame, offset)[0])
            offset += 4

        full_it_present = sum(val << (i * 32) for i, val in enumerate(it_presents))
        radiotap_info.update({
            "version": rth_version, 
            "pad": rth_pad, 
            "length": rth_length, 
            "present": hex(full_it_present)
        })

        for field, (bit, size) in it_present_fields.items():
            if not (full_it_present & (1 << bit)):
                continue
                
            if offset + size > len(frame):
                continue
                
            if size > 1:
                offset = align_offset(offset, size)

            try:
                if field == "channel":
                    freq, flags = struct.unpack_from("<HH", frame, offset)
                    radiotap_info["channel_freq"] = freq
                    radiotap_info["channel_flags"] = flags
                    radiotap_info["is_2ghz"] = bool(flags & 0x0080)
                    radiotap_info["is_5ghz"] = bool(flags & 0x0100)
                    offset += 4
                    
                elif field == "rate":
                    value = struct.unpack_from("<B", frame, offset)[0]
                    radiotap_info[field] = value / 2.0
                    offset += 1
                    
                elif size == 1:
                    if field.startswith("dbm_") or field.startswith("db_"):
                        value = struct.unpack_from("<b", frame, offset)[0]
                    else:
                        value = struct.unpack_from("<B", frame, offset)[0]
                    radiotap_info[field] = value
                    offset += 1
                    
                elif size == 2:
                    radiotap_info[field] = struct.unpack_from("<H", frame, offset)[0]
                    offset += 2
                    
                elif size == 4:
                    radiotap_info[field] = struct.unpack_from("<I", frame, offset)[0]
                    offset += 4
                    
                elif size == 8:
                    radiotap_info[field] = struct.unpack_from("<Q", frame, offset)[0]
                    offset += 8
                    
                elif size == 0:
                    continue
                    
            except struct.error:
                continue

        return radiotap_info, rth_length
