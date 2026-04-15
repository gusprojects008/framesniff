from logging import getLogger
from core.common.parser_utils import (ParseContext, unpack, run_dispatch, detect_fcs)
from core.layers.l2.ieee802.dot11.radiotap import parser as radiotap_parser
from core.layers.l2.ieee802.dot11.parsers import (common, management, control, data)
from core.layers.l2.ieee802.dot11.constants import *

logger = getLogger(__name__)

BODY_DISPATCH = {
    MGMT: management.parser,
    CTRL: control.parser,
    DATA: data.parser
}

def parse(frame: bytes, offset: int = 0) -> dict:
    logger.debug("frame parse")
    try:
        with ParseContext(frame, offset) as ctx:
            ctx.set("rt_hdr", radiotap_parser.parser())
            rt_flags = ctx.get("rt_hdr", {}).get("parsed", {}).get("flags", {})
            if rt_flags.get("bad_fcs"):
                logger.debug("Dropping frame: bad_fcs indicated by radiotap")
                return ctx.result
            ctx.set("fcs", detect_fcs())
            if ctx.offset >= len(ctx.frame):
                logger.debug("Empty 802.11 frame after radiotap, skipping")
                return ctx.result
            ctx.set("mac_hdr", common.mac_header())
            fc = ctx.get("mac_hdr").get("parsed").get("fc")
            logger.debug(f"fc={fc}") 
            frame_type = fc.get("type")
            frame_subtype = fc.get("subtype")
            protected = fc.get("protected", False)
            if protected:
                return unpack()
            logger.debug(f"frametype={frame_type}") 
            body_parser = BODY_DISPATCH.get(frame_type)
            if body_parser is None:
                logger.warning(f"No body parser for frame type={frame_type}, subtype={frame_subtype} skipping...")
                return ctx.result
            ctx.set("body", body_parser(subtype=frame_subtype))
    except Exception as e:
        logger.warning(f"Frames parser error: {e}", exc_info=True)
    return ctx.result
