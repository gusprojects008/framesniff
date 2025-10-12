def ip(frame: bytes, offset: int):
    result = {}
    try:
        unpacked, new_offset = safe_unpack("!BBHHHBBH4s4s", frame, offset)
        if unpacked is None:
            return result, offset
        version_ihl, tos, total_length, identification, flags_frag, ttl, protocol, header_checksum, src, dst = unpacked
        version = version_ihl >> 4
        ihl = version_ihl & 0x0F
        result.update({
            "version": version,
            "ihl": ihl,
            "tos": tos,
            "total_length": total_length,
            "identification": identification,
            "flags": (flags_frag >> 13) & 0x7,
            "fragment_offset": flags_frag & 0x1FFF,
            "ttl": ttl,
            "protocol": protocol,
            "header_checksum": header_checksum,
            "src_ip": socket.inet_ntoa(src),
            "dst_ip": socket.inet_ntoa(dst)
        })
        offset = new_offset
        if total_length > ihl * 4:
            payload_len = total_length - ihl * 4
            result["payload"] = frame[offset:offset + payload_len].hex()
            offset += payload_len
        return result, offset
    except struct.error as error:
        result["error"] = str(error)
        return result, offset

def arp(frame: bytes, offset: int):
    result = {}
    try:
        unpacked, new_offset = safe_unpack("!HHBBH6s4s6s4s", frame, offset)
        if unpacked is None:
            return result, offset
        hw_type, proto_type, hw_size, proto_size, opcode, src_mac, src_ip, dst_mac, dst_ip = unpacked
        result.update({
            "hw_type": hw_type,
            "protocol_type": proto_type,
            "hw_size": hw_size,
            "protocol_size": proto_size,
            "opcode": opcode,
            "src_mac": bytes_for_mac(src_mac),
            "src_ip": socket.inet_ntoa(src_ip),
            "dst_mac": bytes_for_mac(dst_mac),
            "dst_ip": socket.inet_ntoa(dst_ip)
        })
        offset = new_offset
        return result, offset
    except struct.error as error:
        result["error"] = str(error)
        return result, offset

def ipv6(frame: bytes, offset: int):
    result = {}
    try:
        unpacked, new_offset = safe_unpack("!IHBB16s16s", frame, offset)
        if unpacked is None:
            return result, offset
        ver_tc_fl, payload_len, next_header, hop_limit, src, dst = unpacked
        version = (ver_tc_fl >> 28) & 0xF
        traffic_class = (ver_tc_fl >> 20) & 0xFF
        flow_label = ver_tc_fl & 0xFFFFF
        result.update({
            "version": version,
            "traffic_class": traffic_class,
            "flow_label": flow_label,
            "payload_length": payload_len,
            "next_header": next_header,
            "hop_limit": hop_limit,
            "src_ip": socket.inet_ntop(socket.AF_INET6, src),
            "dst_ip": socket.inet_ntop(socket.AF_INET6, dst)
        })
        offset = new_offset
        if payload_len > 0:
            result["payload"] = frame[offset:offset + payload_len].hex()
            offset += payload_len
        return result, offset
    except struct.error as error:
        result["error"] = str(error)
        return result, offset
