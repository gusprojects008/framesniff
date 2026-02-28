import struct
import time
import json
from logging import getLogger
from core.common.parser_utils import (random_mac, unpack, extract_fcs_from_frame, clean_hex_string, iter_packets_from_json, MacVendorResolver)
from core.common.function_utils import (new_file_path)
from core.l2.ieee802.dot11.radiotap_header import RadiotapHeader
from core.l2.ieee802.llc import llc as llc_parser
import core.l2.ieee802.dot11.parsers as dot11_parsers 
from core.l2.ieee802.dot11 import builders
from core.l3 import parsers as l3_parsers
from core.common.constants.ieee802_11 import *
from core.common.constants.l2 import *
from core.common.constants.hashcat import (MESSAGE_PAIR_M1, MESSAGE_PAIR_M2)

logger = getLogger(__name__)

class Frame:
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
        def parse(frame: bytes, subtype: int, protected: bool, offset: int = 0):
            body = {}
            flen = len(frame)
        
            if protected:
                body["payload"] = frame[offset:flen].hex()
                return body

            try:
                if subtype in (MGMT_BEACON, MGMT_PROBE_RESPONSE):
                    fixed_parameters, offset = dot11_parsers.fixed_parameters(frame, offset)
                    body["fixed_parameters"] = fixed_parameters
                    tagged_parameters, offset = dot11_parsers.tagged_parameters(frame, offset)
                    body["tagged_parameters"] = tagged_parameters

                elif subtype == MGMT_ATIM:
                    remaining = flen - offset
                    if remaining >= 2:
                        aid_raw, offset = unpack("<H", frame, offset)
                        body["aid"] = aid_raw & 0x3FFF
                    else:
                        body["aid"] = None
        
                elif subtype in (MGMT_DISASSOCIATION, MGMT_DEAUTHENTICATION):
                    body["reason_code"], offset = unpack("<H", frame, offset)
        
                elif subtype == MGMT_AUTHENTICATION:
                    body["auth_algorithm"], offset = unpack("<H", frame, offset)
                    body["auth_sequence"], offset = unpack("<H", frame, offset)
                    body["status_code"], offset = unpack("<H", frame, offset)
                    if offset < flen:
                        fixed_parameters, offset = dot11_parsers.fixed_parameters(frame, offset)
                        body["fixed_parameters"] = fixed_parameters
                        tagged_parameters, offset = dot11_parsers.tagged_parameters(frame, offset)
                        body["tagged_parameters"] = tagged_parameters
        
                elif subtype == MGMT_ACTION:
                    if offset < flen:
                        body["category"], offset = unpack("B", frame, offset)
                    else:
                        body["category"] = None
                    if offset < flen:
                        body["action"], offset = unpack("B", frame, offset)
                    else:
                        body["action"] = None
                    if offset < flen:
                        fixed_parameters, offset = dot11_parsers.fixed_parameters(frame, offset)
                        body["fixed_parameters"] = fixed_parameters
                        tagged_parameters, offset = dot11_parsers.tagged_parameters(frame, offset)
                        body["tagged_parameters"] = tagged_parameters
        
            except Exception as e:
                logger.debug(f"MGMT Parser error: {e}")
                body["payload"] = frame[offset:flen].hex()
        
            return body
        
    class Control:
        class build:
            @staticmethod
            def rts(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", duration: int = 0):
                pass

        @staticmethod
        def parse(frame: bytes, subtype: int, protected: bool, offset: int = 0) -> dict:
            body = {}
            flen = len(frame)
        
            if protected:
                body["payload"] = frame[offset:flen].hex()
                return body
        
            try:
                if subtype == CTRL_BLOCK_ACK_REQUEST:
                    block_ack_control, offset = unpack("<H", frame, offset)
                    block_ack_start_seq, offset = unpack("<H", frame, offset)
                    body.update({
                        "block_ack_control": block_ack_control,
                        "block_ack_start_seq": block_ack_start_seq
                    })
        
                elif subtype == CTRL_BLOCK_ACK:
                    block_ack_bitmap, offset = unpack("<Q", frame, offset)
                    body.update({
                        "block_ack_bitmap": block_ack_bitmap
                    })
        
                elif subtype == CTRL_PS_POLL:
                    aid, offset = unpack("<H", frame, offset)
                    body.update({
                        "aid": aid & 0x3FFF
                    })
        
                elif subtype == CTRL_ACK:
                    return body
        
                elif subtype == CTRL_CF_END:
                    return body
        
                elif subtype == CTRL_CF_END_ACK:
                    return body
        
                else:
                    body["payload"] = frame[offset:flen].hex()
        
            except Exception as e:
                logger.debug(f"CTRL Parser error: {e}")
                body["payload"] = frame[offset:flen].hex()
        
            return body
    
    class Data:
        class build:
            @staticmethod
            def basic(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", payload = b""):
                pass

        @staticmethod
        def parse(frame: bytes, subtype: int, protected: bool, offset: int = 0) -> dict:
            body = {}
            flen = len(frame)
        
            if protected:
                body["payload"] = frame[offset:flen].hex()
                return body

            if subtype in {DATA_NULL, DATA_CF_ACK, DATA_CF_POLL, DATA_CF_ACK_CF_POLL, 
                           DATA_QOS_NULL, DATA_QOS_CF_POLL, DATA_QOS_CF_ACK_CF_POLL, 
                           DATA_RESERVED}:
                return body

            try:
                llc, llc_offset = llc_parser(frame, offset)
                body["llc"] = llc
                
                llc_type = llc.get("type", "")
            
                if llc_type == LLC_EAPOL:
                    eapol, eapol_offset = dot11_parsers.eapol(frame, llc_offset)
                    body["eapol"] = eapol
            
                elif llc_type == LLC_IPV4:
                    ip, ip_offset = l3_parsers.ip(frame, llc_offset)
                    body["ip"] = ip
            
                elif llc_type == LLC_ARP:
                    arp, arp_offset = l3_parsers.arp(frame, llc_offset)
                    body["arp"] = arp
            
                elif llc_type == LLC_IPV6:
                    ipv6, ipv6_offset = l3_parsers.ipv6(frame, llc_offset)
                    body["ipv6"] = ipv6
            
                elif llc_type in LLC_BODY_NAME:
                    body_name = LLC_BODY_NAME[llc_type]
                    body[body_name] = frame[llc_offset:flen].hex()
            
                else:
                    body["payload"] = frame[llc_offset:flen].hex()
                    
            except Exception as e:
                logger.debug(f"LLC Parser error: {e}")
                body["payload"] = frame[offset:flen].hex()
        
            return body
        
    def frames_parser(frame: bytes, mac_vendor_resolver: object, offset: int = 0) -> dict:
        logger.debug("function frames_parser:")
        parsed_frame = {}
        rt_hdr, rt_hdr_len = RadiotapHeader.parse(frame)
        fcs_bytes, frame_no_rth_and_fcs = extract_fcs_from_frame(frame, rt_hdr_len)
        if len(frame_no_rth_and_fcs) < 2:
            logger.warning("Empty 802.11 frame after radiotap, skipping")
            return {'rt_hdr': rt_hdr, "mac_hdr": None, 'fcs': fcs_bytes.hex() if fcs_bytes else None}
        frame = frame_no_rth_and_fcs
        mac_hdr, mac_hdr_offset = dot11_parsers.mac_header(frame, mac_vendor_resolver)
        parsed_frame = {'rt_hdr': rt_hdr, 'mac_hdr': mac_hdr, "fcs": fcs_bytes.hex() if fcs_bytes else None}
        try:
            frame_type = mac_hdr.get("fc").get("type")
            subtype = mac_hdr.get("fc").get("subtype")
            protected = mac_hdr.get("protected", False)
            logger.debug(f"Parsing frame: type: {frame_type} subtype: {subtype} ...")
            if frame_type == MGMT:
                body = Frame.Management.parse(frame, subtype, protected, mac_hdr_offset)
                parsed_frame["body"] = body
            elif frame_type == CTRL:
                body = Frame.Control.parse(frame, subtype, protected, mac_hdr_offset)
                parsed_frame["body"] = body
            elif frame_type == DATA:
                body = Frame.Data.parse(frame, subtype, protected, mac_hdr_offset)
                parsed_frame["body"] = body
            else:
                parsed_frame["body"] = {"error": f"Unknown frame type {frame_type}"}
        except Exception as e:
            logger.debug(f"Frames parser error: {e}")
        return parsed_frame

    @staticmethod
    def generate_22000(bitmask_message_pair: int = MESSAGE_PAIR_M2, ssid: str = None, input_filename: str = None, output_filename: str = "hashcat.22000"):
        if not input_filename:
            raise ValueError("Input file must be provided.")
    
        output_filename = str(new_file_path("hashcat", ".22000", output_filename))
        essid = ssid.encode("utf-8", errors="ignore").hex()
        message_pair = 0
    
        with open(input_filename, "r") as f:
            data = json.load(f)

        if bitmask_message_pair == MESSAGE_PAIR_M1:
            pmkid = clean_hex_string(data.get("pmkid"))
            ap_mac = clean_hex_string(data.get("ap_mac"))
            sta_mac = clean_hex_string(data.get("sta_mac"))
            if not all([ssid, pmkid, ap_mac, sta_mac]):
                raise ValueError("Missing one or more required keys: pmkid, ap_mac, sta_mac")
            line = f"WPA*01*{pmkid}*{ap_mac}*{sta_mac}*{essid}***{message_pair:02x}"
            logger.info(line)
    
        elif bitmask_message_pair == MESSAGE_PAIR_M2:
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
            mac_hdr1, mac_offset1 = dot11_parsers.mac_header(msg1, mac_vendor_resolver, rth_len1)
            subtype, protected = (mac_hdr1.get("fc").get("subtype"), mac_hdr1.get("protected", False))
            body1 = Frame.Data.parse(msg1, subtype, protected, mac_offset1)
    
            _, rth_len2 = RadiotapHeader.parse(msg2)
            mac_hdr2, mac_offset2 = dot11_parsers.mac_header(msg2, mac_vendor_resolver, rth_len2)
            subtype, protected = (mac_hdr2.get("fc").get("subtype"), mac_hdr2.get("protected", False))
            body2 = Frame.Data.parse(msg2, subtype, protected, mac_offset2)
    
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
    
            llc, llc_offset = llc_parser(msg2, mac_offset2)
            eapol_frame, eapol_frame_offset = dot11_parsers.eapol(msg2, llc_offset)
            eapol_frame = msg2[llc_offset:eapol_frame_offset]
    
            mic_offset = struct.calcsize("!BBHBHHQ32s16s8s8s")
            mic_bytes = eapol_frame[mic_offset:mic_offset + struct.calcsize("16s")]
            zero_mic = b"\x00" * len(mic_bytes)
    
            eapol_zero_mic = (eapol_frame[:mic_offset] + zero_mic + eapol_frame[mic_offset + len(mic_bytes):]).hex()
    
            line = f"WPA*02*{mic}*{ap_mac}*{sta_mac}*{essid}*{anonce}*{eapol_zero_mic}*{message_pair:02x}"
    
            with open(output_filename, "w", newline="\n") as f:
                f.write(line)

            logger.info(line)
        else:
            raise ValueError("Unsupported bitmask_message_pair!")
