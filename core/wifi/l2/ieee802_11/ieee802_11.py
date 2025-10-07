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
        def parse(frame, offset):
            body = {}
            tagged_parameters, tagged_parameters_offset = parsers.tagged_parameters(frame, offset)
            body["tagged_parameters"] = tagged_parameters
            return body

    class Control:
        class build:
            @staticmethod
            def rts(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", duration: int = 0):
                pass

        @staticmethod
        def parse(frame, offset):
            pass
    
    class Data:
        class build:
            @staticmethod
            def basic(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", payload = b""):
                pass

        @staticmethod
        def parse(frame, offset):
            body = {}
            llc, llc_offset = parsers.llc(frame, offset)
            body["llc"] = llc
            if llc.get("type", "") == "0x888e":
                eapol, eapol_offset = parsers.eapol(frame, llc_offset)
                body["eapol"] = eapol
            return body

    @staticmethod
    def frames_parser(raw_frame: bytes) -> dict:
        parsed_frame = {}
        rt_hdr, rt_hdr_len = RadiotapHeader.parse(raw_frame)
        fcs_bytes, ieee80211_without_fcs = extract_fcs_from_frame(raw_frame, rt_hdr_len)
        mac_hdr, mac_hdr_offset = parsers.mac_header(raw_frame, rt_hdr_len)
        if not mac_hdr:
            return parsed_frame
        parsed_frame = {'rt_hdr': rt_hdr, 'mac_hdr': mac_hdr, "fcs": fcs_bytes.hex() if fcs_bytes else None}
        try:
            frame_type = mac_hdr.get("fc").get("type")
            subtype = mac_hdr.get("fc").get("subtype")
            if frame_type == 0:
                body = IEEE802_11.Management.parse(raw_frame, mac_hdr_offset)
                parsed_frame["body"] = body
            elif frame_type == 1:
                parsed_frame["body"] = {"error": "Control frame parser not implemented"}
            elif frame_type == 2:
                body = IEEE802_11.Data.parse(raw_frame, mac_hdr_offset)
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
