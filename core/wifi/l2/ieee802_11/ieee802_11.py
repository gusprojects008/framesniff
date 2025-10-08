import struct
import time
import json
from core.common.useful_functions import (random_mac, safe_unpack, extract_fcs_from_frame, new_file_path, clean_hex_string)
from core.wifi.l2.radiotap_header import RadiotapHeader
from core.wifi.l2.ieee802_11 import parsers
from core.wifi.l2.ieee802_11 import ies_parsers
from core.wifi.l2.ieee802_11 import builders

class IEEE802_11:
    class Management:
        class build:
            @staticmethod
            def deauthentication():
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = random_mac()
                bssid = src_mac
                reason_code = 0x0007
                radiotap = RadiotapHeader.build()
                frame_control = 0x00C0
                mac_header = builders.mac_header(frame_control, dst_mac, src_mac, bssid)
                reason = struct.pack("<H", reason_code)
                frame_bytes = radiotap + mac_header + reason
                return frame_bytes.hex()
    
            @staticmethod
            def probe_request():
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = random_mac()
                bssid = dst_mac
                radiotap = RadiotapHeader.build()
                frame_control = 0x0040
                mac_header = builders.mac_header.build(frame_control, dst_mac, src_mac, bssid)
                tagged_params = Management.build.tagged_parameters()
                frame_bytes = radiotap + mac_header + tagged_params
                return frame_bytes.hex()
    
            @staticmethod
            def beacon():
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = random_mac()
                bssid = src_mac
                radiotap = RadiotapHeader.build()
                frame_control = 0x0080
                mac_header = builders.mac_header(frame_control, dst_mac, src_mac, bssid)
                timestamp = struct.pack("<Q", int(time.time() * 1_000_000))
                beacon_interval = struct.pack("<H", 100)
                capabilities = struct.pack("<H", 0x0431)
                frame_body = timestamp + beacon_interval + capabilities
                tagged_params = Management.build.tagged_parameters()
                frame_bytes = radiotap + mac_header + frame_body + tagged_params
                return frame_bytes.hex()
    
            @staticmethod
            def authentication():
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = random_mac()
                bssid = src_mac
                radiotap = RadiotapHeader.build()
                frame_control = 0x00B0
                mac_header = builders.mac_header(frame_control, dst_mac, src_mac, bssid)
                auth_algorithm = struct.pack("<H", 0x0000)
                auth_seq = struct.pack("<H", 0x0001)
                status_code = struct.pack("<H", 0x0000)
                frame_bytes = radiotap + mac_header + auth_algorithm + auth_seq + status_code
                return frame_bytes.hex()
    
            @staticmethod
            def association_request():
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = random_mac()
                bssid = dst_mac
                radiotap = RadiotapHeader.build()
                frame_control = 0x0000
                mac_header = builder.mac_header(frame_control, dst_mac, src_mac, bssid)
                capabilities = struct.pack("<H", 0x0431)
                listen_interval = struct.pack("<H", 0x0001)
                frame_body = capabilities + listen_interval
                tagged_params = Management.build.tagged_parameters()
                frame_bytes = radiotap + mac_header + frame_body + tagged_params
                return frame_bytes.hex()

        @staticmethod
        def parse(frame: bytes, offset: int, subtype: int, protected: bool):
            body = {}
            flen = len(frame)
        
            if protected:
                body["payload"] = frame[offset:flen].hex()
                return body
        
            def unpack(fmt, off):
                res, new_off = safe_unpack(fmt, frame, off)
                if res is None:
                    return None, off
                if len(res) == 1:
                    return res[0], new_off
                return res, new_off
        
            if subtype == 0:
                tagged_parameters, offset = parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 1:
                tagged_parameters, offset = parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 2:
                tagged_parameters, offset = parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 3:
                tagged_parameters, offset = parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 4:
                tagged_parameters, offset = parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 5:
                tagged_parameters, offset = parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 8:
                tagged_parameters, offset = parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 9:
                remaining = flen - offset
                if remaining >= 2:
                    aid_raw, offset = unpack("<H", offset)
                    body["aid"] = aid_raw & 0x3FFF
                else:
                    body["aid"] = None
            elif subtype == 10:
                body["reason_code"], offset = unpack("<H", offset)
            elif subtype == 11:
                body["auth_algorithm"], offset = unpack("<H", offset)
                body["auth_sequence"], offset = unpack("<H", offset)
                body["status_code"], offset = unpack("<H", offset)
                if offset < flen:
                    try:
                        tagged_parameters, offset = parsers.tagged_parameters(frame, offset)
                        body["tagged_parameters"] = tagged_parameters
                    except Exception:
                        body["extra"] = frame[offset:flen].hex()
            elif subtype == 12:
                body["reason_code"], offset = unpack("<H", offset)
            elif subtype == 13:
                if offset < flen:
                    body["category"], offset = unpack("B", offset)
                else:
                    body["category"] = None
                if offset < flen:
                    body["action"], offset = unpack("B", offset)
                else:
                    body["action"] = None
                if offset < flen:
                    try:
                        tagged_parameters, offset = parsers.tagged_parameters(frame, offset)
                        body["tagged_parameters"] = tagged_parameters
                    except Exception:
                        body["payload"] = frame[offset:flen].hex()
            else:
                body["payload"] = frame[offset:flen]
        
            return body
        
    class Control:
        class build:
            @staticmethod
            def rts(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", duration: int = 0):
                pass

        @staticmethod
        def parse(frame: bytes, offset: int, subtype: int, protected: bool) -> dict:
            body = {}
            flen = len(frame)

            if protected:
                body["payload"] = frame[offset:flen].hex()
                return body

            def unpack(fmt, off):
                res, new_off = safe_unpack(fmt, frame, off)
                if res is None:
                    return None, off
                if len(res) == 1:
                    return res[0], new_off
                return res, new_off

            try:
                if subtype == 8:  # Block Ack Request (BAR)
                    block_ack_control, offset = unpack("<H", offset)
                    block_ack_start_seq, offset = unpack("<H", offset)
                    body.update({
                        "block_ack_control": block_ack_control,
                        "block_ack_start_seq": block_ack_start_seq
                    })

                elif subtype == 9:  # Block Ack (BA)
                    block_ack_bitmap, offset = unpack("<Q", offset)
                    body.update({"block_ack_bitmap": block_ack_bitmap})

                elif subtype == 10:  # PS-Poll
                    aid, offset = unpack("<H", offset)
                    body["aid"] = aid & 0x3FFF

                elif subtype == 11:  # RTS
                    duration, offset = unpack("<H", offset)
                    body["duration"] = duration

                elif subtype == 12:  # CTS
                    duration, offset = unpack("<H", offset)
                    body["duration"] = duration

                elif subtype == 13:  # ACK
                    pass

                elif subtype == 14:  # CF-End
                    pass

                elif subtype == 15:  # CF-End + CF-Ack
                    pass

                else:
                    body["payload"] = frame[offset:flen].hex()

            except Exception as e:
                body["parser_error"] = str(e)
                body["payload"] = frame[offset:flen].hex()

            return body
            pass
    
    class Data:
        class build:
            @staticmethod
            def basic(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", payload = b""):
                pass

        def parse(frame: bytes, offset: int, subtype: int, protected: bool) -> dict:
            body = {}
            flen = len(frame)
        
            llc, llc_offset = parsers.llc(frame, offset)
            body["llc"] = llc
        
            if protected:
                body["payload"] = frame[llc_offset:flen].hex()
                return body
        
            llc_type = llc.get("type", "")
        
            def unpack_parser(parser_func, off):
                try:
                    res, new_off = parser_func(frame, off)
                    return res, new_off
                except Exception:
                    return frame[off:flen].hex(), flen
        
            if llc_type == "0x888e":
                eapol, eapol_offset = unpack_parser(parsers.eapol, llc_offset)
                body["eapol"] = eapol
            elif llc_type == "0x0800":
                ip, ip_offset = unpack_parser(parsers.ip, llc_offset)
                body["ip"] = ip
            elif llc_type == "0x0806":
                arp, arp_offset = unpack_parser(parsers.arp, llc_offset)
                body["arp"] = arp
            elif llc_type == "0x86dd":
                ipv6, ipv6_offset = unpack_parser(parsers.ipv6, llc_offset)
                body["ipv6"] = ipv6
            elif llc_type in ["0x888f", "0x890d", "0x88b4", "0x88b5", "0x88b6", "0x8902", "0x88c0", "0x8903"]:
                body_name = {
                    "0x888f": "mesh_ctrl",
                    "0x890d": "tdls",
                    "0x88b4": "wapi",
                    "0x88b5": "fast_bss_transition",
                    "0x88b6": "dls",
                    "0x8902": "robust_av_streaming",
                    "0x88c0": "wmm",
                    "0x8903": "qos_null"
                }[llc_type]
                body[body_name] = frame[llc_offset:flen].hex()
            else:
                body["payload"] = frame[llc_offset:flen].hex()
        
            return body

    @staticmethod
    def frames_parser(frame: bytes, mac_vendor_resolver) -> dict:
        parsed_frame = {}
        rt_hdr, rt_hdr_len = RadiotapHeader.parse(frame)
        fcs_bytes, frame_no_fcs = extract_fcs_from_frame(frame, rt_hdr_len)
        #frame = frame_no_fcs
        mac_hdr, mac_hdr_offset = parsers.mac_header(frame, rt_hdr_len, mac_vendor_resolver)
        if not mac_hdr:
            return parsed_frame
        parsed_frame = {'rt_hdr': rt_hdr, 'mac_hdr': mac_hdr, "fcs": fcs_bytes.hex() if fcs_bytes else None}
        try:
            protected = mac_hdr.get("protected", False)
            frame_type = mac_hdr.get("fc").get("type")
            subtype = mac_hdr.get("fc").get("subtype")
            if frame_type == 0:
                body = IEEE802_11.Management.parse(frame, mac_hdr_offset, subtype, protected)
                parsed_frame["body"] = body
            elif frame_type == 1:
                parsed_frame["body"] = IEEE802_11.Control.parse(frame, mac_hdr_offset, subtype, protected)
            elif frame_type == 2:
                body = IEEE802_11.Data.parse(frame, mac_hdr_offset, subtype, protected)
                parsed_frame["body"] = body
            else:
                parsed_frame["body"] = {"error": f"Unknown frame type {frame_type}"}
        except Exception as error:
            parsed_frame["body"] = {"parser_error": str(error)}
        return parsed_frame

    @staticmethod
    def generate_22000(bitmask_message_pair: int = 2, ssid: str = None, input_file: str = None, output_file: str = "hashcat.22000", message_pair: int = 0):
        if not input_file:
            raise ValueError("Input file must be provided.")
    
        output_file = new_file_path("hashcat", ".22000", output_file)
        essid = ssid.encode("utf-8", errors="ignore").hex()
    
        with open(input_file, "r") as f:
            data = json.load(f)

        if bitmask_message_pair == 1:
            pmkid = clean_hex_string(data.get("pmkid", ""))
            mac_ap = clean_hex_string(data.get("mac_ap", ""))
            mac_client = clean_hex_string(data.get("mac_client", ""))
            if not all([ssid, pmkid, mac_ap, mac_client]):
                raise ValueError("Missing one or more required keys: pmkid, mac_ap, mac_client")
            line = f"WPA*01*{pmkid}*{mac_ap}*{mac_client}*{essid}***{message_pair:02x}"
            print(line)
    
        elif bitmask_message_pair == 2:
            eapol_msg1_hex = None
            eapol_msg2_hex = None
            seen = 0
    
            for hexstr, _ in iter_packets_from_json(input_file):
                if seen == 0:
                    eapol_msg1_hex = hexstr
                elif seen == 1:
                    eapol_msg2_hex = hexstr
                    break
                seen += 1
    
            if eapol_msg1_hex is None:
                raise ValueError("No frames found in input file")
            if eapol_msg2_hex is None:
                raise ValueError("Only one frame found in input file; need two EAPOL frames")

            msg1 = bytes.fromhex(eapol_msg1_hex)
            msg2 = bytes.fromhex(eapol_msg2_hex)
    
            _, rth_len1 = RadiotapHeader.parse(msg1)
            mac_hdr1, mac_offset1 = parsers.mac_header(msg1, rth_len1)
            body1 = IEEE802_11.Data.parse(msg1, mac_offset1)
    
            _, rth_len2 = RadiotapHeader.parse(msg2)
            mac_hdr2, mac_offset2 = parsers.mac_header(msg2, rth_len2)
            body2 = IEEE802_11.Data.parse(msg2, mac_offset2)
    
            mac_ap = clean_hex_string(mac_hdr2.get("bssid", "") or mac_hdr2.get("mac_dst", ""))
            mac_client = clean_hex_string(mac_hdr2.get("mac_src", "") or mac_hdr2.get("mac_transmitter", ""))
    
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
    
            llc, llc_offset = parsers.llc(msg2, mac_offset2)
            eapol_frame, eapol_frame_offset = parsers.eapol(msg2, llc_offset)
            eapol_frame = msg2[llc_offset:eapol_frame_offset]
    
            mic_offset = struct.calcsize("!BBHBHHQ32s16s8s8s")
            mic_bytes = eapol_frame[mic_offset:mic_offset + struct.calcsize("16s")]
            zero_mic = b"\x00" * len(mic_bytes)
    
            eapol_zero_mic = (eapol_frame[:mic_offset] + zero_mic + eapol_frame[mic_offset + len(mic_bytes):]).hex()
            message_pair_hex = f"{message_pair:02x}"
    
            line = f"WPA*02*{mic}*{mac_ap}*{mac_client}*{essid}*{anonce}*{eapol_zero_mic}*{message_pair_hex}"
    
            with open(output_file, "w", newline="\n") as f:
                f.write(line)

            print(line)
        else:
            raise ValueError("Unsupported bitmask_message_pair. Must be 1 or 2.")
