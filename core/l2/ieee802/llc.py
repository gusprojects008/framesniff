import struct
from logging import getLogger
from core.common.parser_utils import (unpack, bytes_for_mac) 

logger = getLogger(__name__)

def llc(frame: bytes, offset: int):
    logger.debug(f"LLC parser: {frame, offset}")
    result = {}
    (unpacked), offset = unpack("!BBB3sH", frame, offset)
    logger.debug(f"{unpacked}")
    dsap, ssap, control, org_code, llc_type = unpacked
    result.update({
        "dsap": hex(dsap),
        "ssap": hex(ssap),
        "control_field": control,
        "organization_code": bytes_for_mac(org_code),
        "type": hex(llc_type)
    })
    return result, offset
