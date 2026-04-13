from logging import getLogger
from core.common.parser_utils import (ParseContext, unpack, run_dispatch, detect_fcs)
from core.layers.l2.ieee802.dot11.radiotap import parser as radiotap_parser
from core.layers.l2.ieee802.dot11.parsers import (common, management, control, data)

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
            ctx.set("rt_hdr", unpack(parser=radiotap_parser))
            ctx.set("fcs", unpack(parser=detect_fcs, metadata=False))
            ctx.set("mac_hdr", unpack(parser=dot11_common_parsers.mac_header))
            if ctx.offset >= len(ctx.frame):
                logger.warning("Empty 802.11 frame after radiotap, skipping")
                return ctx.result
            fc = ctx.get("mac_hdr").get("fc", {})
            frame_type = fc.get("type")
            frame_subtype = fc.get("subtype")
            protected = fc.get("protected", False)
            if protected:
                return unpack()
            body_parser = BODY_DISPATCH.get(frame_type, {})
            ctx.set("body", unpack(parser=body_parser(frame_subtype)))
            return ctx.result
    except Exception as e:
        logger.debug(f"Frames parser error: {e}")
        return {}
