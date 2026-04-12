from core.common.parser_utils import (ParseContext, unpack, detect_fcs)
from core.l2.ieee802.dot11.radiotap_header import RadiotapHeader
from core.l2.ieee802.dot11.parsers as dot11_parsers

logger = getLogger(__name__)

def parse(frame: bytes, offset: int = 0) -> dict:
    logger.debug("frame parse")
    try:
        with ParseContext(frame, offset) as ctx:
            ctx.set("rt_hdr", unpack(parser=RadiotapHeader.parse))
            ctx.set("fcs", unpack(parser=detect_fcs, metadata=False))
            ctx.set("mac_hdr", unpack(parser=dot11_parsers.mac_header))
            if ctx.offset >= len(ctx.frame):
                logger.warning("Empty 802.11 frame after radiotap, skipping")
                return ctx.result
            ctx.set("body", unpack(parser=dot11_parsers.body_dispatch))
            return ctx.result
    except Exception as e:
        logger.debug(f"Frames parser error: {e}")
        return {}
