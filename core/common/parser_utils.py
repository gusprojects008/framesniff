import json
import re
import binascii
from logging import getLogger
import struct

logger = getLogger(__name__)

wireshark_format = lambda packet_bytes : ":".join(f"{byte:02x}" for byte in packet_bytes)

index_pack = lambda index : struct.pack("<I", index)

def freq_converter(freq_unit: tuple, to_unit: str):
    freq, unit = freq_unit
    unit = unit.lower()
    to_unit = to_unit.lower()
    
    if  unit == 'khz':
        base_freq = freq
    elif unit == 'mhz':
         base_freq = freq * 1000
    elif unit == 'ghz':
         base_freq = freq * 1000000
    else:
        raise ValueError(f"Unidade de origem inválida: {from_unit}. Use 'kHz', 'MHz' ou 'GHz'")
    
    if to_unit == 'khz':
       return base_freq
    elif to_unit == 'mhz':
         return base_freq / 1000
    elif to_unit == 'ghz':
         return base_freq / 1000000
    else:
        raise ValueError(f"Destiny unit invalid: {to_unit}. Use 'kHz', 'MHz' ou 'GHz'")

def bitmap_dict_to_hex(bitmap_dict: dict):
    result = 0
    for i, (field, active) in enumerate(bitmap_dict.items()):
        if active:
            result |= (1 << i)
    return result

def random_mac():
    mac = [random.randint(0x00, 0xFF) for _ in range(6)]
    return ':'.join(f"{hex_byte:02x}" for hex_byte in mac)

def calc_rates(rates):
    list_rates_transmition = []
    for rate in rates:   
        value_rate = (rate & 0x7f) * 500
        list_rates_transmition.append(value_rate)
    return list_rates_transmition

bytes_for_mac = lambda mac : ":".join(format(byte, "02x") for byte in mac)

mac_for_bytes = lambda mac : bytes(int(hex_byte, 16) for hex_byte in mac.split(":"))

def bitmap_value_for_dict(bitmap_value: int, field_names: list[str]) -> dict:
    result = {}
    for i, name in enumerate(field_names):
        result[name] = bool(bitmap_value & (1 << i))
    return result

def unpack(fmt: str, blob: bytes, offset: int = 0):
    size = struct.calcsize(fmt)
    if offset + size > len(blob):
        logger.debug(f"unpack function ERROR: (offset + size) {offset + size} > {len(blob)} (len(blob))\n{fmt, blob, offset} (fmt, blob and offset)", exc_info=True)
        raise ValueError("Trucated blob")
    values = struct.unpack_from(fmt, blob, offset)
    offset += size
    if len(values) == 1:
        return values[0], offset
    return (values), offset

def clean_hex_string(s: str) -> str:
    s = s.strip().strip("'").strip('"')
    return re.sub(r'[^0-9a-fA-F]', '', s).lower()

def iter_packets_from_json(path: str):
    try:
        with open(path, "r") as file:
            content = file.read()
    except Exception as error:
        raise RuntimeError(f"Could not open file {path}: {error}")
    key = "raw"
    try:
        data = json.loads(content)

        if isinstance(data, list):
            for obj in data:
                if not isinstance(obj, dict):
                    continue
                raw = obj.get(key)
                if isinstance(raw, str):
                    cleaned = clean_hex_string(raw)
                    if cleaned:
                        yield (cleaned, bytes.fromhex(cleaned))
                elif isinstance(raw, list):
                    for entry in raw:
                        if not isinstance(entry, str):
                            continue
                        cleaned = clean_hex_string(entry)
                        if cleaned:
                            yield (cleaned, bytes.fromhex(cleaned))
        elif isinstance(data, dict):
            value = data.get(key)
            if isinstance(value, str):
                cleaned = clean_hex_string(value)
                if cleaned:
                    yield (cleaned, bytes.fromhex(cleaned))
            elif isinstance(value, list):
                for entry in value:
                    if not isinstance(entry, str):
                        continue
                    cleaned = clean_hex_string(entry)
                    if cleaned:
                        yield (cleaned, bytes.fromhex(cleaned))

        else:
            raise ValueError("JSON file must contain a dict or list of dicts")

    except json.JSONDecodeError as error:
        raise ValueError(f"Error trying to load json file: {error}")

def extract_fcs_from_frame(frame: bytes, radiotap_len: int) -> Tuple[Optional[bytes], bytes]:
    if radiotap_len is None or radiotap_len < 0 or radiotap_len >= len(frame):
        return None, frame[radiotap_len:]
    payload_11 = frame[radiotap_len:]
    if len(payload_11) < 4:
        return None, payload_11
    candidate_fcs_bytes = payload_11[-4:]
    candidate_fcs = int.from_bytes(candidate_fcs_bytes, byteorder='little')
    data_for_crc = payload_11[:-4]
    calc_crc = binascii.crc32(data_for_crc) & 0xffffffff
    if calc_crc == candidate_fcs:
        return candidate_fcs_bytes, data_for_crc
    else:
        return None, payload_11

class MacVendorResolver:
    _vendor_map = None
    def __init__(self, filepath: str = "./core/common/mac-vendors-export.json"):
        if MacVendorResolver._vendor_map is None:
            logger.debug(f"Loading MAC vendors file {filepath} ...")
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    MacVendorResolver._vendor_map = {
                        item['macPrefix']: item['vendorName'] for item in data
                    }
                logger.debug("MAC vendors loaded successfully.")
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.error(f"Could not load or parse MAC vendors file: {e}")
                MacVendorResolver._vendor_map = {}

    def mac_resolver(self, mac_bytes: bytes):
        if not mac_bytes:
            return None
        mac_address = bytes_for_mac(mac_bytes)
        if not self._vendor_map or not mac_address:
            return None
        oui = mac_address.upper()[:8]
        return {"mac": mac_address, "vendor": self._vendor_map.get(oui, "Unknown")}

def freq_to_channel(freq_mhz) -> int:
    if not freq_mhz:
        return freq_mhz
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if freq_mhz == 2484:
        return 14
    if 5000 <= freq_mhz <= 5895:
        return (freq_mhz - 5000) // 5
    return "Unknown"
