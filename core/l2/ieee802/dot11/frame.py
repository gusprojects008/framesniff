import struct
import time
from core.common.constants.ieee802_11 import *
from core.common.parser_utils import (add_metadata, detect_fcs)
from core.common.function_utils import new_file_path
from core.l2.ieee802.dot11.radiotap_header import RadiotapHeader
from core.l2.ieee802.dot11.frame as dot11_parsers
#from core.l2.ieee802.dot11 import builders
from contextlib import contextmanager

logger = getLogger(__name__)

@contextmanager
def track_offset(frame: bytes, offset: int):
    state = {"start": offset, "current": offset}
    
    def parse_and_track(parser_func, *args, **kwargs):
        state["start"] = state["current"]
        result, state["current"] = parser_func(frame, state["current"], *args, **kwargs)
        result.update(add_metadata(frame, state["start"], state["current"))
        return result, state["current"]
    
    yield parse_and_track, lambda: state["current"]

def parse(frame: bytes, offset: int = 0) -> dict:
    logger.debug("function frame parse:")
    parsed_frame = {}
    
    try:
        with track_offset(frame, offset) as (parse_and_track, get_offset):
            rt_hdr, _ = parse_and_track(RadiotapHeader.parse)
            parsed_frame["rt_hdr"] = rt_hdr
            
            fcs_bytes, _ = parse_and_track(detect_fcs)
            parsed_frame["fcs"] = fcs_bytes.hex() if fcs_bytes else None
            
            mac_hdr, _ = parse_and_track(dot11_parsers.mac_header)
            parsed_frame["mac_hdr"] = mac_hdr
            
            if get_offset() >= len(frame):
                logger.warning("Empty 802.11 frame after radiotap, skipping")
                return parsed_frame
            
            frame_type = mac_hdr.get("fc", {}).get("type")
            frame_subtype = mac_hdr.get("fc", {}).get("subtype")
            protected = mac_hdr.get("fc", {}).get("protected", False)
            
            body, _ = parse_and_track(dot11_parsers.body_dispatch, 
                                     frame_type, frame_subtype, protected)
            parsed_frame["body"] = body
            
    except Exception as e:
        logger.debug(f"Frames parser error: {e}")
    
    return parsed_frame
