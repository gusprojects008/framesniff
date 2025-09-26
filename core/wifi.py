import struct
import socket
import time
import pathlib
import operator
import json
from internal_functions import *
from frames_filter import *

class l7:
     class http:
          @staticmethod
          def parser():
              pass

class l4:
     class tcp:
          @staticmethod
          def parser():
              pass
     class udp:
          @staticmethod
          def parser():
              pass

class l3:
     class arp:
          @staticmethod
          def parser():
              pass

class l2:
    @staticmethod
    def create_socket(ifname):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((ifname, 0))
        return sock
    class ieee802_11:
        class FramesStructure:
            @staticmethod
            def radiotap_header():
                def boolean_fields_to_hex(bitmap_fields):
                    result = 0
                    for i, (field, active) in enumerate(bitmap_fields.items()):
                        if active:
                            result |= (1 << i)
                    return result
                rth_version = struct.pack("<B", 0)
                rth_pad = struct.pack("<B", 0)
                rth_btm_present = {
                    "TSFT": True,
                    "Flags": True,
                    "Rate": True,
                    "Channel": False,
                    "AntennaSignal": True,
                }
                rth_btm_present_int = struct.pack("<I", boolean_fields_to_hex(rth_btm_present))
                rth_mac_timestamp = struct.pack("<Q", 0)

                rth_btm_flags = {
                    "CFP": False,
                    "Preamble": False,
                    "WEP": False,
                    "Fragmentation": False,
                    "FCS": False,
                    "DataPad": False,
                    "BadFCS": False,
                    "ShortGI": False
                }
                rth_btm_flags_int = struct.pack("<B", l2.ieee802_11.FramesStructure.boolean_fields_to_hex(rth_btm_flags))

                rth_data_rate = struct.pack("<B", 5)

                rth_btm_channels = {
                    "2GHZ": True,
                    "5GHZ": True
                }
                rth_btm_channels_int = struct.pack("<H", l2.ieee802_11.FramesStructure.boolean_fields_to_hex(rth_btm_channels))
                rth_antenna_signal = struct.pack("<b", -60)

                radiotap_data = rth_mac_timestamp + rth_btm_flags_int + rth_data_rate + rth_btm_channels_int + rth_antenna_signal
                rth_length = struct.pack("<H", len(rth_version) + len(rth_pad) + len(rth_btm_present_int) + len(radiotap_data))

                return rth_version + rth_pad + rth_length + rth_btm_present_int + radiotap_data

            @staticmethod
            def mac_header(frame_control, receiver_address, transmitter_address):
                duration_id = struct.pack("<H", 0)
                receiver_address = mac_for_bytes(receiver_address)
                transmitter_address = mac_for_bytes(transmitter_address)
                bssid = mac_for_bytes(receiver_address)
                sequence_control = struct.pack("<H", 0)
                return frame_control + duration_id + receiver_address + transmitter_address + bssid + sequence_control

            @staticmethod
            def wireless_management_tagged_parameters(ssid: str):
                ie_tag_number_ssid = struct.pack("<B", 0)
                ie_ssid = ssid.encode("utf-8")
                ie_length_ssid = struct.pack("<B", len(ie_ssid))

                ie_tag_number_rates = struct.pack("<B", 1)
                rates = [0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c]
                ie_rates = b""
                for rate in calc_rates(rates):
                    ie_rates += struct.pack("<B", rate // 500)
                ie_length_rates = struct.pack("<B", len(ie_rates))

                return ie_tag_number_ssid + ie_length_ssid + ie_ssid + ie_tag_number_rates + ie_length_rates + ie_rates

        class SendFrame:
            def __init__(self, sock):
                self.sock = sock

            def send_deauthentication(self, dst_mac, src_mac, reason_code, count: int = 1, delay: int = 1):
                rth_hdr = l2.ieee802_11.FramesStructure.radiotap_header()
                frame_control = struct.pack("<H", 0x00C0)
                mac_hdr = l2.ieee802_11.FramesStructure.mac_header(frame_control, dst_mac, src_mac)
                reason = struct.pack("<H", reason_code)
                frame = rth_hdr + mac_hdr + reason
                for _ in range(count):
                    try:
                        self.sock.send(frame)
                    except Exception:
                        pass
                    time.sleep(delay)

            def send_probe_request(self, src_mac: str = RandomMac(), dst_mac: str = "ff:ff:ff:ff:ff:ff", ssid: str = "", count: int = 1, delay: int = 1):
                rth_hdr = l2.ieee802_11.FramesStructure.radiotap_header()
                frame_control = struct.pack("<H", 0x0040)
                mac_hdr = l2.ieee802_11.FramesStructure.mac_header(frame_control, dst_mac, src_mac)
                tagged_params = l2.ieee802_11.FramesStructure.wireless_management_tagged_parameters(ssid)
                frame = rth_hdr + mac_hdr + tagged_params
                for _ in range(count):
                    try:
                        self.sock.send(frame)
                    except Exception:
                        pass
                    time.sleep(delay)

            def send_beacon(self, dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = RandomMac(), ssid: str = "", count: int = 1, delay: int = 1):
                rth_hdr = l2.ieee802_11.FramesStructure.radiotap_header()
                frame_control = struct.pack("<H", 0x0080)
                mac_hdr = l2.ieee802_11.FramesStructure.mac_header(frame_control, dst_mac, src_mac)
                timestamp = struct.pack("<Q", int(time.time() * 1_000_000))
                beacon_interval = struct.pack("<H", 100)
                capabilities = struct.pack("<H", 0x0431)
                frame_body = timestamp + beacon_interval + capabilities
                ssid_ie = struct.pack("BB", 0, len(ssid)) + ssid.encode()
                frame = rth_hdr + mac_hdr + frame_body + ssid_ie
                for _ in range(count):
                    try:
                        self.sock.send(frame)
                    except Exception:
                        pass
                    time.sleep(delay)

        class FramesParser:
            @staticmethod
            def parser_radiotap_header(frame):
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
            
                full_it_present = 0
                for i, val in enumerate(it_presents):
                    full_it_present |= val << (i * 32)
            
                radiotap_info.update({
                    "rth_version": rth_version,
                    "rth_pad": rth_pad,
                    "rth_length": rth_length,
                    "rth_present": hex(full_it_present)
                })
            
                for field, (bit, size) in it_present_fields.items():
                    if bit >= 32 and len(it_presents) <= bit // 32:
                        continue
                    if full_it_present & (1 << bit):
                        offset = align_offset(offset, size)
                        if offset + size > len(frame):
                            continue
                        if size == 1:
                            value = struct.unpack_from("<B", frame, offset)[0]
                            if field == "dBmAntSignal":
                                value = struct.unpack_from("<b", frame, offset)[0]
                        elif size == 2:
                            value = struct.unpack_from("<H", frame, offset)[0]
                        elif size == 4:
                            value = struct.unpack_from("<I", frame, offset)[0]
                        elif size == 8:
                            value = struct.unpack_from("<Q", frame, offset)[0]
                        else:
                            continue
            
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

            @staticmethod
            def parser_mac_header(frame, offset):
                try:
                    mac_header_size = struct.calcsize("<HH6s6s6sH")
                    if len(frame) < offset + mac_header_size:
                        return None, None
            
                    frame_control, duration_id, addr1, addr2, addr3, sequence_number = struct.unpack_from(
                        "<HH6s6s6sH", frame, offset
                    )
            
                    protocol_version = frame_control & 0b11
                    frame_type = (frame_control >> 2) & 0b11
                    frame_subtype = (frame_control >> 4) & 0b1111
            
                    to_ds = (frame_control >> 8) & 0x01
                    from_ds = (frame_control >> 9) & 0x01
                    addr4 = None
                    if to_ds == 1 and from_ds == 1:
                        if len(frame) >= offset + mac_header_size + 6:
                            addr4 = frame[offset + mac_header_size: offset + mac_header_size + 6]
            
                    mac_receiver = bytes_for_mac(addr1)
                    mac_transmitter = bytes_for_mac(addr2)
                    bssid = bytes_for_mac(addr3)
                    mac_source = None
                    mac_destination = None
            
                    if to_ds == 0 and from_ds == 0:
                        mac_destination = bytes_for_mac(addr1)
                        mac_source = bytes_for_mac(addr2)
                        bssid = bytes_for_mac(addr3)
                    elif to_ds == 0 and from_ds == 1:
                        mac_destination = bytes_for_mac(addr1)
                        mac_source = bytes_for_mac(addr3)
                        bssid = bytes_for_mac(addr2)
                    elif to_ds == 1 and from_ds == 0:
                        mac_destination = bytes_for_mac(addr3)
                        mac_source = bytes_for_mac(addr2)
                        bssid = bytes_for_mac(addr1)
                    elif to_ds == 1 and from_ds == 1:
                        mac_destination = bytes_for_mac(addr3)
                        mac_source = bytes_for_mac(addr4) if addr4 else bytes_for_mac(addr2)
                        bssid = None
            
                    offset += mac_header_size

                    qos_control = None

                    if frame_type == 2 and frame_subtype >= 8:
                        size = struct.calcsize("<H")
                        if offset + size > len(frame):
                            return None, offset
                        qos_control = struct.unpack_from("<H", frame, offset)[0]
                        offset += size

                    return {
                        'FrameControl': hex(frame_control),
                        'ProtocolVersion': protocol_version,
                        'Type': frame_type,
                        'Subtype': frame_subtype,
                        'DurationID': duration_id,
                        'MACReceiver': mac_receiver,
                        'MACTransmitter': mac_transmitter,
                        'MACSource': mac_source,
                        'MACDestination': mac_destination,
                        'BSSID': bssid,
                        'SequenceNumber': sequence_number,
                        'QOS': qos_control
                    }, offset

                except Exception:
                    return None, None

            @staticmethod
            def parser_wireless_management(frame, offset):
                if len(frame) < offset + 8:
                    return None
                timestamp, beacon_interval, capabilities_information = struct.unpack_from("<QHH", frame, offset)
                offset += struct.calcsize("<QHH")

                wireless_info = {'Timestamp': timestamp, 'BeaconInterval': beacon_interval, 'SSID': None, 'SupportedRates': []}

                if len(frame) < offset + 2:
                    return wireless_info
                ssid_tag_number, ssid_length = struct.unpack_from("<BB", frame, offset)
                offset += 2
                if ssid_tag_number == 0 and offset + ssid_length <= len(frame):
                    ssid = struct.unpack_from(f"{ssid_length}s", frame, offset)[0]
                    wireless_info["SSID"] = ssid.decode(errors='ignore')
                    offset += ssid_length

                if len(frame) < offset + 2:
                    return wireless_info
                supported_rates_tag_number, supported_rates_length = struct.unpack_from("<BB", frame, offset)
                offset += 2
                if supported_rates_tag_number == 1 and offset + supported_rates_length <= len(frame):
                    supported_rates = struct.unpack_from(f"<{supported_rates_length}B", frame, offset)
                    wireless_info["SupportedRates"] = [rate // 2 for rate in supported_rates]
                    offset += supported_rates_length

                return wireless_info, offset

            @staticmethod
            def parser_llc(frame, offset):
                size = struct.calcsize("!BBB3sH")
                if offset + size > len(frame):
                    return None, offset
                dsap, ssap, control_field, organization_code, llc_type = struct.unpack_from("!BBB3sH", frame, offset)
                offset += size
                return {
                    "DSAP": hex(dsap),
                    "SSAP": hex(ssap),
                    "ControlField": control_field,
                    "OrganizationCode": bytes_for_mac(organization_code),
                    #"LLCType": f"{hex(llc_type)} 802.1X Authentication" if llc_type == 0x8e88 else f"{hex(llc_type)} Unknown"
                    "LLCType": hex(llc_type)
                    #"LLCType": hex(llc_type)
                }, offset

            @staticmethod
            def parser_eapol(frame, offset):
                size = struct.calcsize("!BBH")
                if offset + size > len(frame):
                    return None, offset
                authentication_version, eapol_type, eapol_hdr_length = struct.unpack_from("!BBH", frame, offset)
                offset += size
            
                size = struct.calcsize("!BHH")
                if offset + size > len(frame):
                    return None, offset
                key_descriptor_type, key_informations, key_length = struct.unpack_from("!BHH", frame, offset)
                offset += size
            
                size = struct.calcsize("!Q32s16s8s8s16sH")
                if offset + size > len(frame):
                    return None, offset
                replay_counter, key_nonce, key_iv, key_rsc, key_id, key_mic, key_data_length = struct.unpack_from(
                    "!Q32s16s8s8s16sH", frame, offset
                )
                offset += size
            
                size = struct.calcsize(f"!{key_data_length}s")
                if offset + size > len(frame):
                    key_data = b""
                else:
                    key_data = struct.unpack_from(f"!{key_data_length}s", frame, offset)[0]
                    offset += size
            
                return {
                   #"AuthenticationVersion": f"{hex(authentication_version)} 802.1X-2001 WPA/WPA2" if authentication_version == 0x1 else f"{hex(authentication_version)} Unknown",
                   "AuthenticationVersion": authentication_version,
                   #"EAPOLType": f"{hex(eapol_type)} EAPOL-key" if eapol_type == 0x3 else f"{hex(eapol_type)} Unknown",
                   "EAPOLType": eapol_type,
                   "HeaderLength": eapol_hdr_length,
                   "KeyDescriptorType": key_descriptor_type,
                   "KeyInformation": key_informations,
                   "KeyLength": key_length,
                   "ReplayCounter": replay_counter,
                   "KeyNonce": key_nonce.hex(),
                   "KeyIV": key_iv.hex(),
                   "KeyRSC": key_rsc.hex(),
                   "KeyID": key_id.hex(),
                   "KeyMIC": key_mic.hex(),
                   "KeyDataLength": key_data_length,
                   "KeyData": key_data.hex() if key_data else None
                }, offset

            @staticmethod
            def frames_parser(raw_frame: bytes) -> dict:
                rth, rth_len = l2.ieee802_11.FramesParser.parser_radiotap_header(raw_frame)
                mac_hdr_result = l2.ieee802_11.FramesParser.parser_mac_header(raw_frame, rth_len)
                if not mac_hdr_result:
                    return {
                        "Raw": raw_frame.hex(),
                        "RadiotapHeader": rth,
                        "ParserError": "Unsupported frame"
                    }
                mac_hdr, mac_hdr_offset = mac_hdr_result
                parsed_frame = {
                    "Raw": raw_frame.hex(),
                    "RadiotapHeader": rth,
                    "MacHeader": mac_hdr
                }
                try:
                    if not mac_hdr:
                        return parsed_frame
                    ftype = mac_hdr.get("Type")
                    subtype = mac_hdr.get("Subtype")
                    if ftype == 0:
                        wireless_management, wireless_offset = l2.ieee802_11.FramesParser.parser_wireless_management(raw_frame, mac_hdr_offset)
                        parsed_frame["WirelessManagement"] = wireless_management
                    elif ftype == 1:
                        parsed_frame["ControlFrame"] = {
                            "Info": "Control frame - no LLC/EAPOL parsing"
                        }
                    elif ftype == 2:
                        llc, llc_offset = l2.ieee802_11.FramesParser.parser_llc(raw_frame, mac_hdr_offset)
                        if llc:
                            parsed_frame["LLC"] = llc
                            if llc.get("LLCType") == '0x888e':
                                eapol, eapol_offset = l2.ieee802_11.FramesParser.parser_eapol(raw_frame, llc_offset)
                                if eapol:
                                    parsed_frame["EAPOL"] = eapol
                    else:
                        parsed_frame["UnknownFrame"] = {"Info": f"Unsupported Type {ftype}"}
                except Exception as error:
                    parsed_frame["ParserError"] = str(error)
                return parsed_frame

            @staticmethod
            def frames_filter(store_filter: str = "", display_filter: str = "", parsed_frame: dict = None):
                if parsed_frame is None:
                    parsed_frame = {}
                if store_filter == "":
                    store_filter_result = True
                else:
                    store_filter_result = parse_filter_expr(store_filter, parsed_frame)
                if display_filter == "":
                    display_filter_result = {
                        "BSSID": parsed_frame.get("MacHeader", {}).get("BSSID"),
                        "MACSource": parsed_frame.get("MacHeader", {}).get("MACSource"),
                        "FrameControl": parsed_frame.get("MacHeader", {}).get("FrameControl")
                    }
                else:
                    display_filter_result = l2.ieee802_11.FramesParser._multi_get(display_filter, parsed_frame)
            
                return store_filter_result, display_filter_result

        def sniff(sock, store_filter: str = "", display_filter: str = "", output_file: str = None):
            base = "framesniff-capture"
            ext = ".json" 
        
            output_file_path = new_file_path(base, ext, output_file)
        
            captured_frames = []
        
            try:
                while True:
                    frame, _ = sock.recvfrom(65535)
                    parsed_frame = l2.ieee802_11.FramesParser.frames_parser(frame)
        
                    store_result, display_result = l2.ieee802_11.FramesParser.frames_filter(store_filter, display_filter, parsed_frame)
        
                    if store_result:
                        captured_frames.append(parsed_frame)
        
                    if display_result:
                        print(display_result)
        
            except KeyboardInterrupt:
                with open(output_file_path, "w") as file:
                    json.dump(captured_frames, file, indent=4)
                print(f"\nSaved {len(captured_frames)} frames to {output_file_path}")

        class WPA2Personal:
            @staticmethod
            def generate_22000(eapol_msg1_hex, eapol_msg2_hex, output_file="hashcat.22000"):
                msg1 = bytes.fromhex(eapol_msg1_hex)
                msg2 = bytes.fromhex(eapol_msg2_hex)

                rth1, rth_len1 = l2.ieee802_11.FramesParser.parser_radiotap_header(msg1)
                mac_hdr1, mac_hdr_offset1 = l2.ieee802_11.FramesParser.parser_mac_header(msg1, rth_len1)
                llc1, llc_offset1 = l2.ieee802_11.FramesParser.parser_llc(msg1, mac_hdr_offset1)
                eapol1, _ = l2.ieee802_11.FramesParser.parser_eapol(msg1, llc_offset1)

                rth2, rth_len2 = l2.ieee802_11.FramesParser.parser_radiotap_header(msg2)
                mac_hdr2, mac_hdr_offset2 = l2.ieee802_11.FramesParser.parser_mac_header(msg2, rth_len2)
                llc2, llc_offset2 = l2.ieee802_11.FramesParser.parser_llc(msg2, mac_hdr_offset2)
                eapol2, _ = l2.ieee802_11.FramesParser.parser_eapol(msg2, llc_offset2)

                ap_mac = mac_hdr1.get("BSSID", "").replace(":", "")
                sta_mac = mac_hdr1.get("MACSource", "").replace(":", "")

                nonce = eapol2.get("KeyNonce", "")
                mic = eapol2.get("KeyMIC", "")
                eapol_len = len(msg2[mac_hdr_offset2:])

                line = f"$WPAPSK${ap_mac}${sta_mac}${nonce}${mic}${eapol_len}:{msg2[mac_offset2:].hex()}\n"

                with open(output_file, "w") as file:
                    file.write(line)

                print(f"[+] 22000 file generated: {output_file}")
                return output_file

if __name__ == "__main__":
   eapol_msg1 = bytes.fromhex('''
00001a002f48000062b2270e00000000
00026c09a000c70000008802ca0006ab
f1d631165c628b80838a5c628b80838a
00000000aaaa03000000888e01030075
02008a001000000000000000015de91b
37c74d1ba0a8919d20c971e890a14da3
b29f979e0ca73323404d9f4366000000
00000000000000000000000000000000
00000000000000000000000000000000
000000000000000000000000000016dd
14000fac0413db5dd8d7b4af25317703
399b3e3016
''')
   eapol_msg2 = bytes.fromhex('''
00001a002f48000045ce270e00000000
00026c09a000df00000088013a015c62
8b80838a06abf1d631165c628b80838a
00000600aaaa03000000888e01030075
02010a00000000000000000001db741d
48ed9b31f27f7c6c654844fb57ef5c69
ca8c57b5843df21f319d106ab3000000
00000000000000000000000000000000
000000000000000000000000002cdadf
ff17d404500929a37d848e7f3a001630
140100000fac040100000fac04010000
0fac028000
''')

   #eapol_rth_hdr, rth_hdr_offset = l2.ieee802_11.FramesParser.parser_radiotap_header(eapol_msg2)
   #eapol_mac_hdr, mac_hdr_offset = l2.ieee802_11.FramesParser.parser_mac_header(eapol_msg2, rth_hdr_offset)
   #print(eapol_rth_hdr)
   #print(eapol_mac_hdr)
   #if eapol_mac_hdr.get("FrameControl") == "0x188":
   #   eapol_info, eapol_info_offset = l2.ieee802_11.FramesParser.parser_eapol(eapol_msg2, mac_hdr_offset)
   #   print(eapol_info)

   parsed_frame = l2.ieee802_11.FramesParser.frames_parser(eapol_msg2)
   print(parsed_frame)
   #store_filter_result, display_filter_result = l2.ieee802_11.FramesParser.frames_filter("MacHeader.BSSID == '5C:62:8B:80:83:8A'", "MacHeader.BSSID, MacHeader.MACSource", parsed_frame)
   store_filter_result, display_filter_result = l2.ieee802_11.FramesParser.frames_filter("MacHeader.BSSID == '5c:62:8b:80:83:8a'", "", parsed_frame)
   #store_filter_result, display_filter_result = l2.ieee802_11.FramesParser.frames_filter("", "", parsed_frame)
   if store_filter_result:
      print(parsed_frame, display_filter_result)

   #sock = l2.create_socket("wlan0")
   #l2.ieee802_11.sniff(sock)

   #from scapy.all import *
   #packet = RadioTap(eapol_msg2)
   #wrpcap("eapol_test.pcap", [packet])
   #print("Arquivo pcap criado: eapol_test.pcap")
