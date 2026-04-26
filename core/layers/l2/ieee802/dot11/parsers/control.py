from core.common.parser import (unpack, run_dispatch)
from core.layers.l2.ieee802.dot11.constants import *

def ctrl_block_ack_request(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        ctrl, start_seq = value
        return {
            "block_ack_control": ctrl,
            "block_ack_start_seq": start_seq
        }
    return unpack("<HH", parser=_parser)

def ctrl_block_ack(**kwargs) -> dict:
    return unpack("<Q", parser=lambda v: {"block_ack_bitmap": v})

def ctrl_ps_poll(**kwargs) -> dict:
    return unpack("<H", parser=lambda v: {"aid": v & 0x3FFF})

def ctrl_ack(**kwargs) -> dict:
    return unpack()

def ctrl_cf_end(**kwargs) -> dict:
    return unpack()

def ctrl_cf_end_ack(**kwargs) -> dict:
    return unpack()

DISPATCH_TABLE = {
    CTRL_BLOCK_ACK_REQUEST: ctrl_block_ack_request,
    CTRL_BLOCK_ACK: ctrl_block_ack,
    CTRL_PS_POLL: ctrl_ps_poll,
    CTRL_ACK: ctrl_ack,
    CTRL_CF_END: ctrl_cf_end,
    CTRL_CF_END_ACK: ctrl_cf_end_ack,
}

def parser(**kwargs):
    return run_dispatch(DISPATCH_TABLE, kwargs.get("subtype"))
