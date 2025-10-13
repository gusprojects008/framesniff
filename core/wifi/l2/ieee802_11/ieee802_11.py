import struct
import time
import json
from core.common.useful_functions import (random_mac, safe_unpack, unpack, extract_fcs_from_frame, new_file_path, clean_hex_string, iter_packets_from_json, MacVendorResolver)
from core.wifi.l2.radiotap_header import RadiotapHeader
from core.wifi.l2.ieee802_11 import parsers as l2_parsers
from core.wifi.l2.ieee802_11 import ies_parsers
from core.wifi.l2.ieee802_11 import builders
from core.wifi.l3 import parsers as l3_parsers

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
        
            if subtype == 0:
                fixed_parameters, offset = l2_parsers.fixed_parameters(frame, offset)
                body["fixed_parameters"] = fixed_parameters
                tagged_parameters, offset = l2_parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 1:
                fixed_parameters, offset = l2_parsers.fixed_parameters(frame, offset)
                body["fixed_parameters"] = fixed_parameters
                tagged_parameters, offset = l2_parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 2:
                fixed_parameters, offset = l2_parsers.fixed_parameters(frame, offset)
                body["fixed_parameters"] = fixed_parameters
                tagged_parameters, offset = l2_parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 3:
                fixed_parameters, offset = l2_parsers.fixed_parameters(frame, offset)
                body["fixed_parameters"] = fixed_parameters
                tagged_parameters, offset = l2_parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 4:
                fixed_parameters, offset = l2_parsers.fixed_parameters(frame, offset)
                body["fixed_parameters"] = fixed_parameters
                tagged_parameters, offset = l2_parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 5:
                fixed_parameters, offset = l2_parsers.fixed_parameters(frame, offset)
                body["fixed_parameters"] = fixed_parameters
                tagged_parameters, offset = l2_parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 8:
                fixed_parameters, offset = l2_parsers.fixed_parameters(frame, offset)
                body["fixed_parameters"] = fixed_parameters
                tagged_parameters, offset = l2_parsers.tagged_parameters(frame, offset)
                body["tagged_parameters"] = tagged_parameters
            elif subtype == 9:
                remaining = flen - offset
                if remaining >= 2:
                    aid_raw, offset = unpack("<H", frame, offset)
                    body["aid"] = aid_raw & 0x3FFF
                else:
                    body["aid"] = None
            elif subtype == 10:
                body["reason_code"], offset = unpack("<H", frame, offset)
            elif subtype == 11:
                body["auth_algorithm"], offset = unpack("<H", frame, offset)
                body["auth_sequence"], offset = unpack("<H", frame, offset)
                body["status_code"], offset = unpack("<H", frame, offset)
                if offset < flen:
                    try:
                        fixed_parameters, offset = l2_parsers.fixed_parameters(frame, offset)
                        body["fixed_parameters"] = fixed_parameters
                        tagged_parameters, offset = l2_parsers.tagged_parameters(frame, offset)
                        body["tagged_parameters"] = tagged_parameters
                    except Exception:
                        body["extra"] = frame[offset:flen].hex()
            elif subtype == 12:
                body["reason_code"], offset = unpack("<H", frame, offset)
            elif subtype == 13:
                if offset < flen:
                    body["category"], offset = unpack("B", frame, offset)
                else:
                    body["category"] = None
                if offset < flen:
                    body["action"], offset = unpack("B", frame, offset)
                else:
                    body["action"] = None
                if offset < flen:
                    try:
                        fixed_parameters, offset = l2_parsers.fixed_parameters(frame, offset)
                        body["fixed_parameters"] = fixed_parameters
                        tagged_parameters, offset = l2_parsers.tagged_parameters(frame, offset)
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

            try:
                if subtype == 4: # Beamforming report poll
                   beamforming_report_poll, offset = unpack("<B", frame, offset)
                   body.update({
                       "beamforming_report_poll": beamforming_report_poll,
                   })
                #if subtype == 5: # VHT/HE NDP Announcement
                #if subtype == 6: # Control frame extension
                #if subtype == 7: # Control wrapper
                if subtype == 8:  # Block Ack Request (BAR)
                    block_ack_control, offset = unpack("<H", frame, offset)
                    block_ack_start_seq, offset = unpack("<H", frame, offset)
                    body.update({
                        "block_ack_control": block_ack_control,
                        "block_ack_start_seq": block_ack_start_seq
                    })
                elif subtype == 9:  # Block Ack (BA)
                    block_ack_bitmap, offset = unpack("<Q", frame, offset)
                    body.update({"block_ack_bitmap": block_ack_bitmap})
                elif subtype == 10:  # PS-Poll
                    aid, offset = unpack("<H", frame, offset)
                    body.update({"aid": aid & 0x3FFF})
                elif subtype == 13:  # ACK
                    return body
                elif subtype == 14:  # CF-End
                    return body
                elif subtype == 15:  # CF-End + CF-Ack
                    return body
                else:
                    body["payload"] = frame[offset:flen].hex()
            except Exception as error:
                body["parser_error"] = str(error)
                body["payload"] = frame[offset:flen].hex()
            return body
    
    class Data:
        class build:
            @staticmethod
            def basic(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", payload = b""):
                pass

        @staticmethod
        def parse(frame: bytes, offset: int, subtype: int, protected: bool) -> dict:
            body = {}
            flen = len(frame)
        
            llc, llc_offset = l2_parsers.llc(frame, offset)
            body["llc"] = llc
        
            if protected:
                body["payload"] = frame[llc_offset:flen].hex()
                return body
        
            llc_type = llc.get("type", "")
        
            if llc_type == "0x888e":
                eapol, eapol_offset = l2_parsers.eapol(frame, llc_offset)
                body["eapol"] = eapol
            elif llc_type == "0x0800":
                ip, ip_offset = l3_parsers.ip(frame, llc_offset)
                body["ip"] = ip
            elif llc_type == "0x0806":
                arp, arp_offset = l3_parsers.arp(frame, llc_offset)
                body["arp"] = arp
            elif llc_type == "0x86dd":
                ipv6, ipv6_offset = l3_parsers.ipv6(frame, llc_offset)
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
    def frames_parser(frame: bytes, mac_vendor_resolver: object) -> dict:
        parsed_frame = {}
        rt_hdr, rt_hdr_len = RadiotapHeader.parse(frame)
        fcs_bytes, frame_no_fcs = extract_fcs_from_frame(frame, rt_hdr_len)
        frame = frame_no_fcs
        mac_hdr, mac_hdr_offset = l2_parsers.mac_header(frame, 0, mac_vendor_resolver)
        parsed_frame = {'rt_hdr': rt_hdr, 'mac_hdr': mac_hdr, "fcs": fcs_bytes.hex() if fcs_bytes else None}
        if not mac_hdr:
            return parsed_frame
        try:
            frame_type = mac_hdr.get("fc").get("type")
            subtype = mac_hdr.get("fc").get("subtype")
            protected = mac_hdr.get("protected", False)
            if frame_type == 0:
                body = IEEE802_11.Management.parse(frame, mac_hdr_offset, subtype, protected)
                parsed_frame["body"] = body
            elif frame_type == 1:
                body = IEEE802_11.Control.parse(frame, mac_hdr_offset, subtype, protected)
                parsed_frame["body"] = body
            elif frame_type == 2:
                body = IEEE802_11.Data.parse(frame, mac_hdr_offset, subtype, protected)
                parsed_frame["body"] = body
            else:
                parsed_frame["body"] = {"error": f"Unknown frame type {frame_type}"}
        except Exception as error:
            parsed_frame["body"] = {"parser_error": str(error)}
        return parsed_frame

    @staticmethod
    def generate_22000(bitmask_message_pair: int = 2, ssid: str = None, input_filename: str = None, output_filename: str = "hashcat.22000"):
        if not input_filename:
            raise ValueError("Input file must be provided.")
    
        output_filename = str(new_file_path("hashcat", ".22000", output_filename))
        essid = ssid.encode("utf-8", errors="ignore").hex()
        message_pair = 0
    
        with open(input_filename, "r") as f:
            data = json.load(f)

        if bitmask_message_pair == 1:
            pmkid = clean_hex_string(data.get("pmkid"))
            ap_mac = clean_hex_string(data.get("ap_mac"))
            sta_mac = clean_hex_string(data.get("sta_mac"))
            if not all([ssid, pmkid, ap_mac, sta_mac]):
                raise ValueError("Missing one or more required keys: pmkid, ap_mac, sta_mac")
            line = f"WPA*01*{pmkid}*{ap_mac}*{sta_mac}*{essid}***{message_pair:02x}"
            print(line)
    
        elif bitmask_message_pair == 2:
            eapol_msg1_hex = None
            eapol_msg2_hex = None
            seen = 0
    
            for hexstr, _ in iter_packets_from_json(input_filename):
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
    
            mac_vendor_resolver = MacVendorResolver()

            _, rth_len1 = RadiotapHeader.parse(msg1)
            mac_hdr1, mac_offset1 = l2_parsers.mac_header(msg1, rth_len1, mac_vendor_resolver)
            subtype, protected = (mac_hdr1.get("fc").get("subtype"), mac_hdr1.get("protected", False))
            body1 = IEEE802_11.Data.parse(msg1, mac_offset1, subtype, protected)
    
            _, rth_len2 = RadiotapHeader.parse(msg2)
            mac_hdr2, mac_offset2 = l2_parsers.mac_header(msg2, rth_len2, mac_vendor_resolver)
            subtype, protected = (mac_hdr2.get("fc").get("subtype"), mac_hdr2.get("protected", False))
            body2 = IEEE802_11.Data.parse(msg2, mac_offset2, subtype, protected)
    
            ap_mac = clean_hex_string(mac_hdr2.get("bssid").get("mac") or mac_hdr2.get("mac_dst").get("mac"))
            sta_mac = clean_hex_string(mac_hdr2.get("mac_src").get("mac") or mac_hdr2.get("mac_transmitter").get("mac"))
    
            eapol_data1 = body1.get("eapol", {})
            eapol_data2 = body2.get("eapol", {})
    
            anonce = eapol_data1.get("key_nonce", "")
            mic = eapol_data2.get("key_mic", "")
            if not all([ap_mac, sta_mac, anonce, mic]):
                raise ValueError("Missing essential EAPOL data")
            if len(mic) != 32:
                raise ValueError(f"Invalid MIC length: {len(mic)}")
            if len(anonce) != 64:
                raise ValueError(f"Invalid ANonce length: {len(anonce)}")
    
            llc, llc_offset = l2_parsers.llc(msg2, mac_offset2)
            eapol_frame, eapol_frame_offset = l2_parsers.eapol(msg2, llc_offset)
            eapol_frame = msg2[llc_offset:eapol_frame_offset]
    
            mic_offset = struct.calcsize("!BBHBHHQ32s16s8s8s")
            mic_bytes = eapol_frame[mic_offset:mic_offset + struct.calcsize("16s")]
            zero_mic = b"\x00" * len(mic_bytes)
    
            eapol_zero_mic = (eapol_frame[:mic_offset] + zero_mic + eapol_frame[mic_offset + len(mic_bytes):]).hex()
    
            line = f"WPA*02*{mic}*{ap_mac}*{sta_mac}*{essid}*{anonce}*{eapol_zero_mic}*{message_pair:02x}"
    
            with open(output_filename, "w", newline="\n") as f:
                f.write(line)

            print(line)
        else:
            raise ValueError("Unsupported bitmask_message_pair. Must be 1 or 2.")
