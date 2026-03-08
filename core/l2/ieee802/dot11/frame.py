import struct
import time
import json
from logging import getLogger
from core.common.parser_utils import (random_mac, unpack, extract_fcs_from_frame, clean_hex_string, iter_packets_from_json, MacVendorResolver)
from core.common.function_utils import (new_file_path)
from core.l2.ieee802.dot11.radiotap_header import RadiotapHeader
from core.l2.ieee802 import llc as llc_parser
from core.l2.ieee802.dot11 import builders
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
        def parse(frame: bytes, subtype: int, protected: bool, offset: int = 0) -> dict:
            body = {}
            flen = len(frame)

            payload = frame[offset:flen].hex()

            if protected:
                body["payload"] = payload
                return body

            try:
                handler = MGMT_SUBTYPE_DISPATCH.get(subtype)

                if handler:
                    name = handler.get("name", str(subtype))
                    parser = handler.get("parser")
                else:
                    name = str(subtype)
                    parser = None

                body[name] = {}

                start_offset = offset

                if parser:
                    content, offset = parser(frame, offset)
                    body[name].update(content)

                body[name]["raw"] = frame[start_offset:offset].hex()
                body[name]["start_offset"] = start_offset
                body[name]["end_offset"] = offset

            except Exception as e:
                logger.debug(f"MGMT Parser error: {e}")
                body["payload"] = payload

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
    
            payload = frame[offset:flen].hex()
    
            if protected:
                body["payload"] = payload
                return body
    
            try:
                handler = CTRL_SUBTYPE_DISPATCH.get(subtype)
    
                if handler:
                    name = handler.get("name", str(subtype))
                    parser = handler.get("parser")
                else:
                    name = str(subtype)
                    parser = None
    
                body[name] = {}
    
                start_offset = offset
    
                if parser:
                    content, offset = parser(frame, offset)
                    body[name].update(content)
    
                body[name]["raw"] = frame[start_offset:offset].hex()
                body[name]["start_offset"] = start_offset
                body[name]["end_offset"] = offset
    
            except Exception as e:
                logger.debug(f"CTRL Parser error: {e}")
                body["payload"] = payload
    
            return body
        
    class Data:
        class build:
            @staticmethod
            def basic(dst_mac: str = "ff:ff:ff:ff:ff:ff", src_mac: str = "ff:ff:ff:ff:ff:ff", payload = b""):
                pass

        @staticmethod
        def parse(frame: bytes, subtype: int, protected: bool, offset: int = 0) -> dict:
            llc, offset = llc_parser.llc(frame, offset)
            return llc, offset
        
    def parse(frame: bytes, mac_vendor_resolver: object, offset: int = 0) -> dict:
        logger.debug("function frame parse:")
    
        parsed_frame = {}
        ctx = ParserContext()
        token = CURRENT_CONTEXT.set(ctx)

        try:
            rt_hdr, offset = RadiotapHeader.parse(frame, offset)
        
            fcs_bytes, frame_end = detect_fcs(frame, offset)
        
            mac_hdr, offset = dot11_parsers.mac_header(frame, mac_vendor_resolver, offset)
        
            parsed_frame = {
                "rt_hdr": rt_hdr,
                "mac_hdr": mac_hdr,
                "fcs": fcs_bytes.hex() if fcs_bytes else None
            }
    
            if frame_end - offset < 2:
                logger.warning("Empty 802.11 frame after radiotap, skipping")
                return parsed_frame 

            frame_type = mac_hdr.get("fc").get("type")
            subtype = mac_hdr.get("fc").get("subtype")
            protected = mac_hdr.get("protected", False)
    
            logger.debug(f"Parsing frame: type: {frame_type} subtype: {subtype}")
    
            if frame_type == MGMT:
                body = Frame.Management.parse(frame, subtype, protected, offset)
            elif frame_type == CTRL:
                body = Frame.Control.parse(frame, subtype, protected, offset)
            elif frame_type == DATA:
                body = Frame.Data.parse(frame, subtype, protected, offset)
            else:
                body = {}
    
            parsed_frame["body"] = body
            # parsed_frame["parse_tree"] = 
    
        except Exception as e:
            logger.debug(f"Frames parser error: {e}")

        finally:
            CURRENT_CONTEXT.reset(token)
    
        return parsed_frame
