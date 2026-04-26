from logging import getLogger
from core.common.parser import (ParseContext, unpack, read_oui, bitmap_value_for_dict, insert_item)
from core.layers.l2.ieee802.dot11.constants import *
from core.layers.l2.ieee802.dot11.parsers.ies import ie_dispatch

logger = getLogger(__name__)

# Parsers that can be used in both management frames and data frames

def fixed_parameters(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        ts, interval, cap_raw = value
        
        cap_list = [
            "ess_capabilities", "ibss_status", "reserved1", "reserved2",
            "privacy", "short_preamble", "critical_update_flag",
            "nontransmitted_bssid_critical_update_flag", "spectrum_management",
            "qos", "short_slot_time", "automatic_power_save_delivery",
            "radio_measurement", "epd", "reserved3", "reserved4",
        ]
        
        capabilities = bitmap_value_for_dict(cap_raw, cap_list)
        
        return {
            "timestamp": ts,
            "beacon_interval": interval,
            "capabilities_information": capabilities
        }

    result = {}

    try:
        result = unpack("<QHH", parser=_parser)
    except Exception as e:
       logger.debug(f"Parser fixed parameters error: {e}")

    return result

def tagged_parameters(value: bytes = None, **kwargs) -> dict:
    logger.debug(f"Tagged parameters parser{' (callback mode)' if value is not None else ''}")

    ies_container = {}
    ctx = ParseContext.current()
    
    if value is not None:
        limit = ctx.offset
        ctx.offset -= len(value)
    else:
        max_length = kwargs.get('max_length', 0)
        limit = (ctx.offset + max_length) if max_length else len(ctx.frame)

    while ctx.offset + MIN_IE_LEN <= limit:
        try:
            ie_entry = unpack("<BB", parser=ie_dispatch, **kwargs)
            
            parsed_data = ie_entry.get("parsed", {})
            tag_name = parsed_data.get("name") or parsed_data.get("tag_number")
            
            insert_item(ies_container, tag_name, ie_entry)
        except Exception as e:
            logger.error(f"Error parsing IE at offset {ctx.offset}: {e}")
            break

    ctx.offset = limit
    return ies_container
