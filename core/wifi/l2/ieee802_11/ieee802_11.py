import socket
import struct
import time
import json
import re
from ....common.useful_functions import *
from ....common.filter_engine import apply_filters
from ..radiotap_header import RadiotapHeader
from ....common.sockets import create_raw_socket

class IEEE802_11:
    class Parsers:
        @staticmethod
        def _get_frame_type_subtype_name(frame_type, subtype):
            type_names = {0: "Management", 1: "Control", 2: "Data"}
            subtype_names = {
                0: {0: "Association Request", 1: "Association Response", 2: "Reassociation Request", 
                    3: "Reassociation Response", 4: "Probe Request", 5: "Probe Response", 6: "Timing Advertisement", 
                    8: "Beacon", 9: "ATIM", 10: "Disassociation", 11: "Authentication", 12: "Deauthentication", 
                    13: "Action", 14: "Action No Ack"},
                1: {8: "Block Ack Request", 9: "Block Ack", 10: "PS-Poll", 11: "RTS", 12: "CTS", 
                    13: "ACK", 14: "CF-End", 15: "CF-End+CF-Ack"},
                2: {i: name for i, name in enumerate([
                    "Data", "Data+CF-Ack", "Data+CF-Poll", "Data+CF-Ack+CF-Poll", "Null", 
                    "CF-Ack", "CF-Poll", "CF-Ack+CF-Poll", "QoS Data", "QoS Data+CF-Ack", 
                    "QoS Data+CF-Poll", "QoS Data+CF-Ack+CF-Poll", "QoS Null", "Reserved", 
                    "QoS CF-Poll", "QoS CF-Ack+CF-Poll"])}
            }
            type_name = type_names.get(frame_type, f"Unknown ({frame_type})")
            subtype_name = subtype_names.get(frame_type, {}).get(subtype, f"Unknown {type_name} ({subtype})")
            return type_name, subtype_name

        @staticmethod
        def mac_header(frame, offset):
            try:
                size = struct.calcsize("<HH6s6s6sH")
                if len(frame) < offset + size:
                    return None, None

                frame_control, duration_id, addr1, addr2, addr3, sequence_number = struct.unpack_from("<HH6s6s6sH", frame, offset)
                protocol_version = frame_control & 0b11
                frame_type = (frame_control >> 2) & 0b11
                frame_subtype = (frame_control >> 4) & 0b1111
                frame_type_name, frame_subtype_name = IEEE802_11.Parsers._get_frame_type_subtype_name(frame_type, frame_subtype)

                to_ds = (frame_control >> 8) & 1
                from_ds = (frame_control >> 9) & 1
                addr4 = frame[offset + size: offset + size + 6] if to_ds and from_ds and len(frame) >= offset + size + 6 else None

                mac_receiver = bytes_for_mac(addr1)
                mac_transmitter = bytes_for_mac(addr2)
                bssid = bytes_for_mac(addr3)
                mac_source, mac_destination = None, None

                if to_ds == 0 and from_ds == 0:
                    mac_source, mac_destination = mac_transmitter, mac_receiver
                elif to_ds == 0 and from_ds == 1:
                    mac_source, mac_destination = bytes_for_mac(addr3), mac_receiver
                    bssid = mac_transmitter
                elif to_ds == 1 and from_ds == 0:
                    mac_source, mac_destination = mac_transmitter, bytes_for_mac(addr3)
                    bssid = mac_receiver
                elif to_ds == 1 and from_ds == 1:
                    mac_source, mac_destination = bytes_for_mac(addr4) if addr4 else mac_transmitter, bytes_for_mac(addr3)
                    bssid = None

                offset += size
                mac_data = {
                    "fc": {
                        "protocol_version": protocol_version,
                        "type": frame_type,
                        "type_name": frame_type_name,
                        "subtype": frame_subtype,
                        "subtype_name": frame_subtype_name,
                        "tods": to_ds,
                        "fromdS": from_ds,
                    },
                    "mac_receiver": mac_receiver,
                    "mac_transmitter": mac_transmitter,
                }

                if frame_type == 0 or frame_type == 2:
                    mac_data.update({
                        "mac_src": mac_source,
                        "mac_dst": mac_destination,
                        "bssid": bssid,
                        "sequence_number": sequence_number
                    })
                    if frame_type == 2 and frame_subtype >= 8 and offset + 2 <= len(frame):
                        mac_data["qos_control"] = struct.unpack_from("<H", frame, offset)[0]
                        offset += 2

                return mac_data, offset
            except Exception as error:
                print(f"mac_hdr Error: {error}")
                return None, None

        @staticmethod
        def tagged_parameters(frame, offset):
            if len(frame) < offset + 8:
                return None
            timestamp, beacon_interval, capabilities_information = struct.unpack_from("<QHH", frame, offset)
            offset += struct.calcsize("<QHH")
            tagged_parameters = {'timestamp': timestamp, 'beacon_interval': beacon_interval, 'ssid': None, 'supported_rates': []}
            if len(frame) < offset + 2:
                return tagged_parameters
            ssid_tag_number, ssid_length = struct.unpack_from("<BB", frame, offset)
            offset += 2
            if ssid_tag_number == 0 and offset + ssid_length <= len(frame):
                ssid = struct.unpack_from(f"{ssid_length}s", frame, offset)[0]
                tagged_parameters["ssid"] = ssid.decode(errors='ignore')
                offset += ssid_length
            if len(frame) < offset + 2:
                return tagged_parameters
            supported_rates_tag_number, supported_rates_length = struct.unpack_from("<BB", frame, offset)
            offset += 2
            if supported_rates_tag_number == 1 and offset + supported_rates_length <= len(frame):
                supported_rates = struct.unpack_from(f"<{supported_rates_length}B", frame, offset)
                tagged_parameters["supported_rates"] = [rate // 2 for rate in supported_rates]
                offset += supported_rates_length
            return tagged_parameters, offset
    
        @staticmethod
        def llc(frame, offset):
            size = struct.calcsize("!BBB3sH")
            if offset + size > len(frame):
                return None, offset
            
            dsap, ssap, control, org_code, llc_type = struct.unpack_from("!BBB3sH", frame, offset)
            offset += size
            
            return {
                "dsap": hex(dsap), "ssap": hex(ssap), "control_field": control,
                "organization_code": bytes_for_mac(org_code), "type": hex(llc_type)
            }, offset
    
        @staticmethod
        def eapol(frame, offset):
            # EAPOL Header
            size = struct.calcsize("!BBH")
            if offset + size > len(frame): return None, offset
            auth_ver, eapol_type, length = struct.unpack_from("!BBH", frame, offset)
            offset += size
    
            # Key Descriptor
            size = struct.calcsize("!BHH")
            if offset + size > len(frame): return None, offset
            desc_type, key_info, key_len = struct.unpack_from("!BHH", frame, offset)
            offset += size
    
            # Key Data
            size = struct.calcsize("!Q32s16s8s8s16sH")
            if offset + size > len(frame): return None, offset
            replay, nonce, iv, rsc, key_id, mic, data_len = struct.unpack_from("!Q32s16s8s8s16sH", frame, offset)
            offset += size
            
            key_data = b""
            if data_len > 0 and offset + data_len <= len(frame):
                key_data = frame[offset:offset+data_len]
                offset += data_len
                
            return {
                "authentication_version": auth_ver, "type": eapol_type, "header_length": length,
                "key_descriptor_type": desc_type, "key_information": key_info, "key_length": key_len,
                "replay_counter": replay, "key_nonce": nonce.hex(), "key_iv": iv.hex(),
                "key_rsc": rsc.hex(), "key_id": key_id.hex(), "key_mic": mic.hex(),
                "key_data_length": data_len, "key_data": key_data.hex()
            }, offset

    class Management:
        class build:
            @staticmethod
            def mac_header(frame_control, receiver_address, transmitter_address, bssid=None, duration=0, sequence=0):
                duration_id = struct.pack("<H", duration)
                receiver_addr = mac_for_bytes(receiver_address)
                transmitter_addr = mac_for_bytes(transmitter_address)
                bssid_addr = mac_for_bytes(bssid or transmitter_address)
                sequence_control = struct.pack("<H", sequence & 0xFFF)
                
                return (frame_control + duration_id + receiver_addr + 
                       transmitter_addr + bssid_addr + sequence_control)
    
            @staticmethod
            def tagged_parameters(ssid="", rates: list = None, **kwargs):
                if rates is None:
                    rates = [0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c]
                
                tagged_data = b""
                
                if ssid is not None:
                    ie_ssid = ssid.encode("utf-8")
                    tagged_data += struct.pack("<BB", 0, len(ie_ssid)) + ie_ssid
                
                if rates:
                    ie_rates = b"".join(struct.pack("<B", rate // 500) for rate in calc_rates(rates))
                    tagged_data += struct.pack("<BB", 1, len(ie_rates)) + ie_rates
                
                if 'channel' in kwargs:
                    channel = kwargs['channel']
                    tagged_data += struct.pack("<BB", 3, 1) + struct.pack("<B", channel)
                
                if 'tim' in kwargs:
                    tim_data = kwargs['tim']
                    tagged_data += struct.pack("<BB", 5, len(tim_data)) + tim_data
                
                if 'extended_rates' in kwargs:
                    ext_rates = kwargs['extended_rates']
                    ie_ext_rates = b"".join(struct.pack("<B", rate // 500) for rate in calc_rates(ext_rates))
                    tagged_data += struct.pack("<BB", 50, len(ie_ext_rates)) + ie_ext_rates
                
                return tagged_data
    
            @staticmethod
            def deauthentication(dst_mac, src_mac, bssid=None, reason_code=0x0007, **kwargs):
                radiotap = RadiotapHeader.build(**kwargs)
                frame_control = struct.pack("<H", 0x00C0)  # Management + Deauthentication
                mac_header = IEEE802_11.Management.build.mac_header(
                    frame_control, dst_mac, src_mac, bssid)
                reason = struct.pack("<H", reason_code)
                frame_bytes = radiotap + mac_header + reason
                return frame_bytes.hex()
            
            @staticmethod
            def probe_request(src_mac, dst_mac="ff:ff:ff:ff:ff:ff", ssid="", rates=None, **kwargs):
                radiotap = RadiotapHeader.build(**kwargs)
                frame_control = struct.pack("<H", 0x0040)  # Management + Probe Request
                mac_header = IEEE802_11.Management.build.mac_header(
                    frame_control, dst_mac, src_mac, dst_mac)  # BSSID = destino para probe requests
                tagged_params = IEEE802_11.Management.build.tagged_parameters(
                    ssid=ssid, rates=rates)
                frame_bytes = radiotap + mac_header + tagged_params
                return frame_bytes.hex()
            
            @staticmethod
            def beacon(src_mac, dst_mac="ff:ff:ff:ff:ff:ff", ssid="", beacon_interval=100, 
                      rates=None, channel=None, capabilities=0x0431, **kwargs):
                radiotap = RadiotapHeader.build(**kwargs)
                frame_control = struct.pack("<H", 0x0080)  # Management + Beacon
                mac_header = IEEE802_11.Management.build.mac_header(
                    frame_control, dst_mac, src_mac, src_mac)  # BSSID = MAC do AP
                
                # Beacon frame body
                timestamp = struct.pack("<Q", int(time.time() * 1_000_000))
                beacon_interval_packed = struct.pack("<H", beacon_interval)
                capabilities_packed = struct.pack("<H", capabilities)
                frame_body = timestamp + beacon_interval_packed + capabilities_packed
                
                # Tagged parameters
                tagged_params = IEEE802_11.Management.build.tagged_parameters(
                    ssid=ssid, rates=rates, channel=channel)
                
                frame_bytes = radiotap + mac_header + frame_body + tagged_params
                return frame_bytes.hex()
    
            @staticmethod
            def authentication(dst_mac, src_mac, bssid=None, auth_algorithm=0x0000, 
                              auth_seq=0x0001, status_code=0x0000, **kwargs):
                radiotap = RadiotapHeader.build(**kwargs)
                frame_control = struct.pack("<H", 0x00B0)  # Management + Authentication
                mac_header = IEEE802_11.Management.build.mac_header(
                    frame_control, dst_mac, src_mac, bssid)
                
                auth_body = struct.pack("<HHH", auth_algorithm, auth_seq, status_code)
                frame_bytes = radiotap + mac_header + auth_body
                return frame_bytes.hex()
    
            @staticmethod
            def association_request(dst_mac, src_mac, ssid, rates=None, capabilities=0x0431, **kwargs):
                radiotap = RadiotapHeader.build(**kwargs)
                frame_control = struct.pack("<H", 0x0000)  # Management + Association Request
                mac_header = IEEE802_11.Management.build.mac_header(
                    frame_control, dst_mac, src_mac, dst_mac)
                
                # Association request body
                capabilities_packed = struct.pack("<H", capabilities)
                listen_interval = struct.pack("<H", 0x0001)  # Listen interval padrão
                
                frame_body = capabilities_packed + listen_interval
                tagged_params = IEEE802_11.Management.build.tagged_parameters(
                    ssid=ssid, rates=rates)
                
                frame_bytes = radiotap + mac_header + frame_body + tagged_params
                return frame_bytes.hex()

        @staticmethod
        def parser(frame, offset):
            body = {}
            tagged_parameters, tagged_parameters_offset = IEEE802_11.Parsers.tagged_parameters(frame, offset)
            body["tagged_parameters"] = tagged_parameters
            return body

    class Control:
        class build:
            @staticmethod
            def rts(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", duration: int = 0):
                pass

        @staticmethod
        def parser(frame, offset):
            pass
    
    class Data:
        class build:
            @staticmethod
            def basic(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", payload = b""):
                pass

        @staticmethod
        def parser(frame, offset):
            body = {}
            llc, llc_offset = IEEE802_11.Parsers.llc(frame, offset)
            body["llc"] = llc
            if llc.get("type", "") == "0x888e":
                eapol, eapol_offset = IEEE802_11.Parsers.eapol(frame, llc_offset)
                body["eapol"] = eapol
            return body

    @staticmethod
    def frames_parser(raw_frame: bytes) -> dict:
        parsed_frame = {}
        rth, rth_len = RadiotapHeader.parse(raw_frame)
        mac_hdr, mac_hdr_offset = IEEE802_11.Parsers.mac_header(raw_frame, rth_len)
        if not mac_hdr:
            return parsed_frame
        parsed_frame = {'rt_hdr': rth, 'mac_hdr': mac_hdr}
        try:
            frame_type = mac_hdr.get("fc").get("type")
            subtype = mac_hdr.get("fc").get("subtype")
            if frame_type == 0:
                body = IEEE802_11.Management.parser(raw_frame, mac_hdr_offset)
                parsed_frame["body"] = body or {}
            elif frame_type == 1:
                parsed_frame["body"] = {"error": "Control frame parser not implemented"}
            elif frame_type == 2:
                body = IEEE802_11.Data.parser(raw_frame, mac_hdr_offset)
                parsed_frame["body"] = body or {}
            else:
                parsed_frame["body"] = {"error": f"Unknown frame type {frame_type}"}
        except Exception as error:
            parsed_frame["body"] = {"parser_error": str(error)}
        return parsed_frame
        
    @staticmethod
    def sniff(ifname: str = None, store_filter: str = "", display_filter: str = "",
              output_file: str = None, count: int = None, timeout: int = None, display_interval: float = 1.0):
        if not ifname:
            raise ValueError("Interface name is required")
    
        sock = create_raw_socket(ifname)
        base = "framesniff-capture"
        ext = ".json"
        output_file_path = new_file_path(base, ext, output_file)
        captured_frames = []
        frame_count = 0
        last_display_time = 0.0
    
        try:
            if timeout:
                sock.settimeout(timeout)
    
            print(f"Starting capture on {ifname}... (Press Ctrl+C to stop)")
            start_time = time.time()
    
            while True:
                try:
                    frame, _ = sock.recvfrom(65535)
                    parsed_frame = IEEE802_11.frames_parser(frame)
                    parsed_frame["raw"] = frame.hex()
    
                    store_result, display_result = apply_filters(store_filter, display_filter, parsed_frame)
    
                    if store_result:
                        captured_frames.append(parsed_frame)
                        frame_count += 1
    
                    if store_result and display_result:
                       try:
                           print(f"[{frame_count}] {json.dumps(display_result, ensure_ascii=False)}")
                       except Exception:
                           print(f"[{frame_count}] {display_result}")
    
                    if count is not None and count > 0 and frame_count >= count:
                        break

                    
                except socket.timeout:
                    print("Capture timeout reached")
                    break
                except KeyboardInterrupt:
                    print("\nCapture interrupted by user")
                    break
                except Exception as error:
                    print(f"Error receiving frame: {error}")
                    continue
        finally:
            sock.close()
            capture_duration = start_time - time.time()
            if captured_frames:
                with open(output_file_path, "w") as file:
                    json.dump(captured_frames, file, indent=2)
                print(f"\nCaptured {len(captured_frames)} frames in {capture_duration:.2f}s")
                print(f"Saved to: {output_file_path}")
            else:
                print("\nNo frames captured")

    class WPA2Personal:
        @staticmethod
        def eapol_capture(ifname: str = None, bssid: str = None, mac: str = None,
                          output_file: str = None, count: int = None, timeout: int = None):
            filters = ["mac_hdr.fc.type == 2"]
            display_fields = ["raw", "mac_hdr", "body.eapol"]

            if bssid:
                filters.append(f"mac_hdr.bssid == '{bssid}'")
            if mac:
                filters.append(f"mac_hdr.mac_src == '{mac}' or mac_hdr.mac_dst == '{mac}'")

            store_filter = " and ".join(filters)
            display_filter = ", ".join(display_fields)

            base = "framesniff-eapol-capture"
            ext = ".json" 
            output_file_path = new_file_path(base, ext, output_file)    

            IEEE802_11.sniff(ifname=ifname, store_filter=store_filter, display_filter=display_filter,
                             output_file=output_file_path, count=count, timeout=timeout)

        @staticmethod
        def generate_22000(ssid: str = None, eapol_msg1: str = None, eapol_msg2: str = None,
                           output_file: str = "hashcat.22000", message_pair: int = 0):
        
            if not all([ssid, eapol_msg1, eapol_msg2]):
                raise ValueError("Essential data required! Need (ssid, eapol message 1, eapol message 2)")
        
            def clean_hex(s):
                return "".join(re.findall(r"[0-9a-fA-F]", s)).lower()
        
            output_file = new_file_path("hashcat", ".22000", output_file)
        
            msg1 = bytes.fromhex(clean_hex(eapol_msg1))
            msg2 = bytes.fromhex(clean_hex(eapol_msg2))
        
            _, rth_len1 = RadiotapHeader.parse(msg1)
            mac_hdr1, mac_offset1 = IEEE802_11.Parsers.mac_header(msg1, rth_len1)
            body1 = IEEE802_11.Data.parser(msg1, mac_offset1)
        
            _, rth_len2 = RadiotapHeader.parse(msg2)
            mac_hdr2, mac_offset2 = IEEE802_11.Parsers.mac_header(msg2, rth_len2)
            body2 = IEEE802_11.Data.parser(msg2, mac_offset2)
        
            mac_ap = clean_hex(mac_hdr2.get("bssid", "") or mac_hdr2.get("mac_dst", ""))
            mac_client = clean_hex(mac_hdr2.get("mac_src", "") or mac_hdr2.get("mac_transmitter", ""))
        
            eapol_data1 = body1.get("eapol", {})
            eapol_data2 = body2.get("eapol", {})
        
            anonce = eapol_data1.get("key_nonce", "")
            mic = eapol_data2.get("key_mic", "")
            if not all([mac_ap, mac_client, anonce, mic]):
                raise ValueError("Missing essential EAPOL data")
            if len(mic) != 32:
                raise ValueError(f"Invalid MIC length: {len(mic)}")
            if len(anonce) != 64:
                raise ValueError(f"Invalid ANonce length: {len(anonce)}")
        
            essid = ssid.encode("utf-8", errors="ignore").hex()
        
            llc, llc_offset = IEEE802_11.Parsers.llc(msg2, mac_offset2)
            eapol_frame, eapol_frame_offset = IEEE802_11.Parsers.eapol(msg2, llc_offset)
            eapol_frame = msg2[llc_offset:eapol_frame_offset]
            
            mic_offset = struct.calcsize("!BBHBHHQ32s16s8s8s")
            mic_bytes = eapol_frame[mic_offset:mic_offset + struct.calcsize("16s")]
            zero_mic = b"\x00" * len(mic_bytes)
            
            eapol_zero_mic = (eapol_frame[:mic_offset] + zero_mic + eapol_frame[mic_offset + len(mic_bytes):]).hex()
        
            try:
                message_pair_int = int(message_pair)
            except:
                raise ValueError("message_pair must be an integer")
            if not (0 <= message_pair_int <= 255):
                raise ValueError("message_pair out of range")
        
            message_pair_hex = f"{message_pair_int:02x}"
            line = f"WPA*02*{mic}*{mac_ap}*{mac_client}*{essid}*{anonce}*{eapol_zero_mic}*{message_pair_hex}\n"
        
            with open(output_file, "w", newline="\n") as f:
                f.write(line)
        
            print()
            print(line)

            return output_file
