from logging import getLogger
from core.common.parser import (ParseContext, unpack, run_dispatch)
from core.layers.l2.ieee802.dot11.parsers import (management, control, data)
from core.layers.l2.ieee802.dot11.constants import *

logger = getLogger(__name__)

BODY_DISPATCH = {
    MGMT: management.parser,
    CTRL: control.parser,
    DATA: data.parser
}

def parser(**kwargs):
    result = {}
    ctx = ParseContext.current()
    fc = ctx.get("mac_hdr").get("parsed").get("fc")
    logger.debug(f"fc={fc}") 
    frame_type = fc.get("type")
    frame_subtype = fc.get("subtype")
    protected = fc.get("protected", False)
    if protected:
        return unpack()
    logger.debug(f"frametype={frame_type}") 
    try:
        result = run_dispatch(BODY_DISPATCH, frame_type, subtype=frame_subtype)
    except Exception as e:
        logger.debug(f"Body parser error: {e}")
    return result
