from logging import getLogger
from core.common.parser_utils import (ParseContext, unpack, bytes_for_mac, bitmap_value_for_dict)
from core.layers.l2.ieee802.dot11.constants import *
from core.layers.l2.ieee802.dot11.parsers.ies import ie_dispatch

logger = getLogger(__name__)

# Parsers that can be used in both management frames and data frames
def mac_header(**kwargs) -> dict:
    logger.debug("MAC Header parse")

    def _parser(fc_val: int, **k) -> dict:
        protocol_version = fc_val & 0b11
        f_type = (fc_val >> 2) & 0b11
        f_subtype = (fc_val >> 4) & 0b1111
        to_ds = (fc_val >> 8) & 1
        from_ds = (fc_val >> 9) & 1
        protected = bool(fc_val & 0x4000)
        
        type_name = FRAME_TYPES.get(f_type)
        subtype_name = FRAME_SUBTYPES.get(f_type, {}).get(f_subtype)
        is_qos = f_type == DATA and bool(f_subtype & 0b1000)

        duration = unpack("<H")
        
        addr1 = bytes_for_mac()
        
        addr2 = addr3 = addr4 = seq = qos = None

        if f_type == CTRL:
            if f_subtype in (CTRL_BLOCK_ACK_REQUEST, CTRL_BLOCK_ACK, CTRL_PS_POLL, 
                             CTRL_RTS, CTRL_CF_END, CTRL_CF_END_ACK):
                addr2 = bytes_for_mac()
        else:
            addr2 = bytes_for_mac()
            addr3 = bytes_for_mac()
            seq_res = unpack("<H")
            seq = seq_res >> 4

            if to_ds and from_ds:
                addr4 = bytes_for_mac()

        ra = addr1
        ta = addr2 if addr2 else None
        a3 = addr3 if addr3 else None
        a4 = addr4 if addr4 else None

        sa = da = bssid = None
        if to_ds == 0 and from_ds == 0:
            sa, da, bssid = ta, ra, a3
        elif to_ds == 0 and from_ds == 1:
            sa, da, bssid = a3, ra, ta
        elif to_ds == 1 and from_ds == 0:
            sa, da, bssid = ta, a3, ra
        elif to_ds == 1 and from_ds == 1:
            sa, da, bssid = a4, a3, None

        # QoS Control
        if is_qos:
            qos = unpack("<H")

        return {
            "fc": {
                "protocol_version": protocol_version,
                "type": f_type,
                "type_name": type_name,
                "subtype": f_subtype,
                "subtype_name": subtype_name,
                "tods": to_ds,
                "fromds": from_ds,
                "protected": protected,
            },
            "duration_id": duration,
            "ra": ra, "ta": ta, "sa": sa, "da": da, "bssid": bssid,
            "sequence_number": seq,
            "qos_control": qos
        }

    return unpack("<H", parser=_parser)

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

    return unpack("<QHH", parser=_parser)

def tagged_parameters(max_length: int = None, **kwargs) -> tuple[dict, int]:
    logger.debug(f"Parsing tagged parameters: offset={offset}")

    def _insert_ie(container: dict, key: str | int, value: dict | str | int):
        if key not in container:
            container[key] = value
            return
        if not isinstance(container[key], dict) or not all(k.isdigit() for k in container[key]):
            container[key] = {"1": container[key]}
        idx = str(len(container[key]) + 1)
        container[key][idx] = value

    ctx = ParseContext.current()
    ies_container = {}

    limit = (ctx.offset + max_length) if max_length else len(ctx.frame)

    while ctx.offset + MIN_IE_LEN <= limit:
        ie_entry = unpack("<BB", parser=ie_dispatch, **kwargs)
        
        parsed_data = ie_entry.get("parsed")
        tag_name = parsed_data.get("name") or parsed_data.get("tag_number")
        
        _insert_ie(ies_container, tag_name, ie_entry)

    return ies_container
