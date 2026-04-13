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

