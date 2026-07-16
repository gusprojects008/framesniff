from logging import getLogger
from core.common.parser import (unpack, read_mac)
from core.layers.l2.ieee802.dot11.constants import *

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
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
        
        addr1 = read_mac()
        
        addr2 = addr3 = addr4 = seq = qos = None

        if f_type == CTRL:
            if f_subtype in (CTRL_BLOCK_ACK_REQUEST, CTRL_BLOCK_ACK, CTRL_PS_POLL, 
                             CTRL_RTS, CTRL_CF_END, CTRL_CF_END_ACK):
                addr2 = read_mac() 
        else:
            addr2 = read_mac() 
            addr3 = read_mac() 
            seq = unpack("<H", parser=lambda v, **k: v >> 4)

            if to_ds and from_ds:
                addr4 = read_mac() 

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

    result = {}

    try:
        result = unpack("<H", parser=_parser)
    except Exception as e:
        logger.debug(f"MAC Header parser error: {e}")

    return result
