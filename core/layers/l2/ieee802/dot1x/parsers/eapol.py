from logging import getLogger
from core.common.parser_utils import (unpack, bytes_for_oui)
from core.layers.l2.ieee802.dot11.parsers.common import tagged_parameters
from core.layers.l2.ieee802.dot1x.constants import *
from core.layers.l2.ieee802.llc.constants import *

logger = getLogger(__name__)

# Parsers payloads LLC of the IEEE 80211 standard
def parser(**kwargs) -> dict:
    logger.debug("EAPOL Parser")
    result = {}
    def _parser(value: tuple, **kwargs) -> dict:
        logger.debug("EAPOL _parser")
        auth_ver, eapol_type, length, desc_type, key_info, key_len, replay, nonce, iv, rsc, key_id, mic, key_data_len = value

        version_map = {
            0: "reserved(0)",
            1: "HMAC_MD5_ARC4_WPA1",
            2: "HMAC_SHA1_128_AES_WPA2_RSN",
            3: "AES_128_CMAC_AES_128_GCMP_WPA3",
            **{i: f"reserved({i})" for i in range(4, 8)},
        }

        key_descriptor_version = key_info & 0x0007
        key_descriptor_version = {"value": key_descriptor_version, "description": version_map.get(key_descriptor_version)}
        key_type_bit = (key_info >> 3) & 0x01
        key_type = {"value": key_type_bit, "description": "group_smk" if key_type_bit else "pairwise"}
        key_index = (key_info >> 4) & 0x03
        install_bit = bool((key_info >> 6) & 0x01)
        ack_bit = bool((key_info >> 7) & 0x01)
        mic_bit = bool((key_info >> 8) & 0x01)
        secure_bit = bool((key_info >> 9) & 0x01)
        error_bit = bool((key_info >> 10) & 0x01)
        request_bit = bool((key_info >> 11) & 0x01)
        encrypted_key_data = bool((key_info >> 12) & 0x01)
        smk_message = bool((key_info >> 13) & 0x01)

        result = {
            "authentication_version": auth_ver,
            "type": eapol_type,
            "header_length": length,
            "key_descriptor_type": desc_type,
            "key_information": {
                "key_descriptor_version": key_descriptor_version,
                "key_type": key_type,
                "key_index": key_index,
                "install": install_bit,
                "key_ack": ack_bit,
                "key_mic": mic_bit,
                "secure": secure_bit,
                "error": error_bit,
                "request": request_bit,
                "encrypted_key_data": encrypted_key_data,
                "smk_message": smk_message,
            },
            "key_length": key_len,
            "replay_counter": replay,
            "key_nonce": nonce,
            "key_iv": iv,
            "key_rsc": rsc,
            "key_id": key_id,
            "key_mic": mic,
            "key_data_length": key_data_len,
        }

        if key_data_len > 0:
            fmt = f"{key_data_len}s"
            if not encrypted_key_data:
                result["key_data"] = unpack(fmt, parser=tagged_parameters) if not encrypted_key_data else unpack(fmt)

        return result

    try:
        fmt = (
            "!BBHBHH"
            f"{EAPOL_KEY_REPLAY_COUNTER_LENGTH}s{EAPOL_KEY_NONCE_LENGTH}s"
            f"{EAPOL_KEY_IV_LENGTH}s{EAPOL_KEY_RSC_LENGTH}s"
            f"{EAPOL_KEY_ID_LENGTH}s{EAPOL_KEY_MIC_LENGTH}s"
            f"{EAPOL_KEY_DATA_LENGTH}"
        )

        logger.debug(f"EAPOL fmt: {fmt!r}")

        result = unpack(fmt, parser=_parser)

    except Exception as e:
        logger.debug(f"EAPOL Parser error: {e}")

    return result
