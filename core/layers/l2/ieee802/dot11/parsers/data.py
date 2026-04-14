from logging import getLogger
from core.layers.l2.ieee802.llc.parser import parser as llc_parser
from core.layers.l2.ieee802.dot11.constants import *

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
    subtype = kwargs.get("subtype")
    logger.debug(f"DATA Parser - Subtype: {subtype}")
    
    body = {}

    if subtype in NULL_DATA_SUBTYPES:
        logger.debug("Null Data frame detected: skipping LLC parser")
        return body
    
    try:
        body["llc"] = llc_parser()
    except Exception as e:
        logger.warning(f"Could not parse LLC on data frame: {e}")
    
    return body
