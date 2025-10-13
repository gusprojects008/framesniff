def mac_header(frame_control: int = 0x0000, receiver_address: str = "ff:ff:ff:ff:ff:ff",
          transmitter_address: str = "ff:ff:ff:ff:ff:ff", bssid: str = None,
          duration: int = 0, sequence: int = 0):
    frame_control_bytes = struct.pack("<H", frame_control)
    duration_bytes = struct.pack("<H", duration)
    receiver_bytes = mac_for_bytes(receiver_address)
    transmitter_bytes = mac_for_bytes(transmitter_address)
    bssid_bytes = mac_for_bytes(bssid or transmitter_address)
    sequence_bytes = struct.pack("<H", sequence & 0xFFF)
    return frame_control_bytes + duration_bytes + receiver_bytes + transmitter_bytes + bssid_bytes + sequence_bytes


def tagged_parameters():
    rates = [0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c]
    tagged_data = b""
    ssid = "TestSSID".encode("utf-8")
    tagged_data += struct.pack("<BB", 0, len(ie_ssid)) + ie_ssid
    ie_rates = b"".join(struct.pack("<B", rate // 500) for rate in calc_rates(rates))
    tagged_data += struct.pack("<BB", 1, len(ie_rates)) + ie_rates
    channel = kwargs['channel']
    tagged_data += struct.pack("<BB", 3, 1) + struct.pack("<B", channel)
    tim_data = kwargs['tim']
    tagged_data += struct.pack("<BB", 5, len(tim_data)) + tim_data
    ext_rates = kwargs['extended_rates']
    ie_ext_rates = b"".join(struct.pack("<B", rate // 500) for rate in calc_rates(ext_rates))
    tagged_data += struct.pack("<BB", 50, len(ie_ext_rates)) + ie_ext_rates
    return tagged_data
