from logging import getLogger
from core.common.parser import (unpack, bytes_for_oui)
from core.layers.l2.ieee802.dot11.parsers.common import tagged_parameters
from core.layers.l2.ieee802.dot1x.constants import *
from core.layers.l2.ieee802.llc.constants import *

logger = getLogger(__name__)

# Parsers payloads LLC of the IEEE 80211 standard
def parser(**kwargs) -> dict:
    def describe_eapol(parsed: dict) -> dict:
        def _classify_eapol_message(parsed: dict) -> int:
            ki = eapol.get("key_information", {})
            ack  = ki.get("key_ack", False)
            mic  = ki.get("key_mic", False)
            inst = ki.get("install", False)
            sec  = ki.get("secure", False)
            enc  = ki.get("encrypted_key_data", False)
            klen = eapol.get("key_data_length", 0)
        
            if     ack and not mic and not sec:  return 1  # AP → STA, ANonce
            if not ack and     mic and not sec:  return 2  # STA → AP, SNonce + MIC
            if     ack and     mic and inst:     return 3  # AP → STA, GTK cifrado
            if not ack and     mic and sec:      return 4  # STA → AP, confirmação
    
            return 0
    
        eapol_msg = _classify_eapol_message(parsed)
    
        ki = parsed["key_information"]
        enc = "WPA3" if parsed["authentication_version"] == 3 else \
              "WPA2/RSN" if parsed["authentication_version"] == 2 else "WPA1"
    
        kd_ver = ki["key_descriptor_version"]["value"]
        cipher_desc = {
            1: "RC4 (WPA1/TKIP)",
            2: "AES-CCM (WPA2/CCMP)",
            3: "AES-GCM (WPA3/GCMP)"
        }.get(kd_ver, f"unknown({kd_ver})")
    
        msg_desc = {
            1: "AP → STA: ANonce (início do 4-way handshake)",
            2: "STA → AP: SNonce + MIC (resposta com credencial)",
            3: "AP → STA: GTK cifrado (instalação de chave)",
            4: "STA → AP: Confirmação (handshake completo)",
        }.get(eapol_msg, "Mensagem EAPOL desconhecida")
    
        flags = []
        if eapol_msg in (1, 2):
            flags.append("HANDSHAKE_CAPTURABLE")   # par M1+M2 → hashcat 22000
        if ki.get("encrypted_key_data"):
            flags.append("KEY_DATA_ENCRYPTED")
        if not ki.get("key_mic") and eapol_msg == 1:
            flags.append("NO_MIC")                 # esperado no msg1
    
        return {
            "summary": f"EAPOL Key (Message {eapol_msg} of 4) [{enc}]",
            "details": {
                "message": eapol_msg,
                "encryption": enc,
                "cipher_suite": cipher_desc,
                "direction": "AP→STA" if eapol_msg in (1, 3) else "STA→AP",
            },
            "flags": flags
        }

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

    logger.debug("EAPOL Parser")
    result = {}

    try:
        fmt = (
            "!BBHBHH"
            f"{EAPOL_KEY_REPLAY_COUNTER_LENGTH}s{EAPOL_KEY_NONCE_LENGTH}s"
            f"{EAPOL_KEY_IV_LENGTH}s{EAPOL_KEY_RSC_LENGTH}s"
            f"{EAPOL_KEY_ID_LENGTH}s{EAPOL_KEY_MIC_LENGTH}s"
            f"{EAPOL_KEY_DATA_LENGTH}"
        )

        logger.debug(f"EAPOL fmt: {fmt!r}")

        #result = unpack(fmt, parser=_parser, descriptor=describe_eapol)
        result = unpack(fmt, parser=_parser)

    except Exception as e:
        logger.debug(f"EAPOL Parser error: {e}")

    return result
