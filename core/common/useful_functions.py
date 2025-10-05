import struct
import random
import socket
import sys
import re
import json
import time
from pathlib import Path
from typing import Optional

wireshark_format = lambda packet_bytes : ":".join(f"{byte:02x}" for byte in packet_bytes)

index_pack = lambda index : struct.pack("<I", index)

ifname_to_ifindex = lambda ifname : index_pack(socket.if_nametoindex(ifname))

def freq_converter(freq_unit: tuple, to_unit: str):
    freq, unit = freq_tuple
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

def new_file_path(base: str, ext: str, output_file: Optional[str] = None) -> Path:
    base = Path(base)
    i = 0
    if output_file:
        candidate_path = Path(f"{output_file}")
    else:
        candidate_path = Path(f"{base}{i}{ext}")

    while candidate_path.exists():
        i += 1
        if output_file:
            candidate_path = Path(f"{i}-{output_file}")
        else:
            candidate_path = Path(f"{base}{i}{ext}")

    return candidate_path

def import_dpkt():
    try:
        import dpkt
        return True
    except Exception as error:
        print(f'''
    {error}
    Error when trying to import dpkt, run the following commands:\n
    python -m venv venv
    source venv/bin/activate
    pip install dpkt
    python {' '.join(sys.argv)}
''')
        return False

# returns the hexadecimal contents of a dictionary of a bitmap.
def bitmap_dict_to_hex(bitmap_dict: dict):
    result = 0
    for i, (field, active) in enumerate(bitmap_dict.items()):
        if active:
            result |= (1 << i)
    return result

def RandomMac():
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

def safe_unpack(fmt: str, frame: bytes, offset: int):
    size = struct.calcsize(fmt)
    if offset + size > len(frame):
        return None, offset
    return struct.unpack_from(fmt, frame, offset), offset + size

def clean_hex_string(s: str) -> str:
    s = s.strip().strip("'").strip('"')
    #if len(s) % 2 != 0: May malform the package!!
     #s = s[:-1]
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
