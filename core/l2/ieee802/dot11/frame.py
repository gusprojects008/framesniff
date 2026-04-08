import struct
import time
from core.common.parser_utils import (random_mac, unpack, extract_fcs_from_frame, clean_hex_string, iter_packets_from_json, MacVendorResolver)
from core.common.function_utils import (new_file_path)
from core.l2.ieee802.dot11.radiotap_header import RadiotapHeader
from core.l2.ieee802 import llc as llc_parser
from core.l2.ieee802.dot11 import builders
from core.common.constants.ieee802_11 import *
from core.common.constants.l2 import *
from core.common.constants.hashcat import (MESSAGE_PAIR_M1, MESSAGE_PAIR_M2)

logger = getLogger(__name__)

def parse(frame: bytes, offset: int = 0) -> dict:
    logger.debug("function frame parse:")
    parsed_frame = {}
    try:
        rt_hdr, offset = RadiotapHeader.parse(frame, offset)
        fcs_bytes, offset  = detect_fcs(frame, offset)
        fcs_hex = fcs_bytes.hex() if fcs_bytes else None
        mac_hdr, offset = dot11_parsers.mac_header(frame, offset)
        parsed_frame = {
            "rt_hdr": rt_hdr,
            "mac_hdr": mac_hdr,
            "fcs": fcs_hex
        }
        if frame_end - offset < 2:
            logger.warning("Empty 802.11 frame after radiotap, skipping")
            return parsed_frame 
        frame_type = mac_hdr.get("fc").get("type")
        frame_subtype = mac_hdr.get("fc").get("subtype")
        protected = mac_hdr.get("fc").get("protected", False)
        logger.debug(f"Parsing frame: type: {frame_type} subtype: {frame_subtype}")
        body, _ = frame_dispatch(frame, frame_type, frame_subtype, protected, offset)
        parsed_frame["body"] = body
    except Exception as e:
        logger.debug(f"Frames parser error: {e}")
    return parsed_frame
