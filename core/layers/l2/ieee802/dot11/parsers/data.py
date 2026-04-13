from logging import getLogger
from core.layers.l2.ieee802.llc.parser import parser as llc_parser

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
    logger.debug("DATA Parser")
    body = {}
    body["llc"] = llc_parser()
    return body
