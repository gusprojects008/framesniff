import struct

class RadiotapHeader:
    @staticmethod
    def boolean_fields_to_hex(bitmap_fields):
        result = 0
        for i, (field, active) in enumerate(bitmap_fields.items()):
            if active:
                result |= (1 << i)
        return result

    @staticmethod
    def header(**kwargs):
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
            "TSFT": config["tsft"],
            "Flags": config["flags"],
            "Rate": config["rate"],
            "Channel": config["channel"],
            "AntennaSignal": config["antenna_signal"],
        }
        rth_btm_present_int = struct.pack("<I", Radiotap.boolean_fields_to_hex(rth_btm_present))
        rth_mac_timestamp = struct.pack("<Q", config["mac_timestamp"])
        rth_btm_flags = {k: False for k in ["CFP", "Preamble", "WEP", "Fragmentation", "FCS", "DataPad", "BadFCS", "ShortGI"]}
        rth_btm_flags_int = struct.pack("<B", Radiotap.boolean_fields_to_hex(rth_btm_flags))
        rth_data_rate = struct.pack("<B", config["data_rate"])
        rth_btm_channels = {"2GHZ": True, "5GHZ": True}
        rth_btm_channels_int = struct.pack("<H", Radiotap.boolean_fields_to_hex(rth_btm_channels))
        rth_antenna_signal = struct.pack("<b", config["antenna_signal_dbm"])

        radiotap_data = rth_mac_timestamp + rth_btm_flags_int + rth_data_rate + rth_btm_channels_int + rth_antenna_signal
        rth_length = struct.pack("<H", len(rth_version) + len(rth_pad) + len(rth_btm_present_int) + len(radiotap_data))
        return rth_version + rth_pad + rth_length + rth_btm_present_int + radiotap_data

    @staticmethod
    def parser(frame):
        def align_offset(offset, alignment):
            return (offset + (alignment - 1)) & ~(alignment - 1)

        radiotap_info = {}
        offset = 0
        if len(frame) < 8:
            return None, offset

        rth_version, rth_pad, rth_length, rth_present = struct.unpack_from("<BBHI", frame, offset)
        offset += struct.calcsize("<BBHI")

        it_present_fields = {
            "TSFT": (0, 8),
            "Flags": (1, 1),
            "Rate": (2, 1),
            "Channel": (3, 4),
            "FHSS": (4, 2),
            "dBmAntSignal": (5, 1),
            "dBmAntNoise": (6, 1),
            "LockQuality": (7, 2),
            "TXAttenuation": (8, 2),
            "dBmTXAttenuation": (9, 1),
            "dBmTXPower": (10, 1),
            "Antenna": (11, 1),
            "dBAntSignal": (12, 1),
            "dBAntNoise": (13, 1),
            "RXFlags": (14, 2),
            "TXFlags": (15, 2),
            "RTSRestries": (16, 1),
            "DataRetries": (17, 1),
            "FrameTimestamp": (22, 8),
            "ExtPresent": (31, 4)
        }

        it_presents = [rth_present]
        while it_presents[-1] & (1 << it_present_fields["ExtPresent"][0]):
            if offset + 4 > len(frame):
                break
            it_presents.append(struct.unpack_from("<I", frame, offset)[0])
            offset += 4

        full_it_present = sum(val << (i * 32) for i, val in enumerate(it_presents))
        radiotap_info.update({"Version": rth_version, "Pad": rth_pad, "Length": rth_length, "Present": hex(full_it_present)})

        for field, (bit, size) in it_present_fields.items():
            if bit >= 32 and len(it_presents) <= bit // 32:
                continue
            if full_it_present & (1 << bit):
                offset = align_offset(offset, size)
                if offset + size > len(frame):
                    continue
                value = None
                if size == 1:
                    value = struct.unpack_from("<b" if field == "dBmAntSignal" else "<B", frame, offset)[0]
                elif size == 2:
                    value = struct.unpack_from("<H", frame, offset)[0]
                elif size == 4:
                    value = struct.unpack_from("<I", frame, offset)[0]
                elif size == 8:
                    value = struct.unpack_from("<Q", frame, offset)[0]
                if field == "Rate":
                    value = value / 2
                if field == "Channel":
                    freq, flags = struct.unpack_from("<HH", frame, offset)
                    radiotap_info["Channel"] = freq
                    radiotap_info["2GHZ"] = bool(flags & 0x0080)
                    radiotap_info["5GHZ"] = bool(flags & 0x0100)
                    offset += 4
                    continue
                radiotap_info[field] = value
                offset += size

        return radiotap_info, rth_length
