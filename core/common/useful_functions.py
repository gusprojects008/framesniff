import struct
import random
import socket
import sys
from pathlib import Path
from typing import Optional

bytes_for_mac = lambda mac : ":".join(format(byte, "02x") for byte in mac)

mac_for_bytes = lambda mac : bytes(int(hex_byte, 16) for hex_byte in mac.split(":"))

wireshark_format = lambda packet_bytes : ":".join(f"{byte:02x}" for byte in packet_bytes)

index_pack = lambda index : struct.pack("<I", index)

ifname_to_ifindex = lambda ifname : index_pack(socket.if_nametoindex(ifname))

def RandomMac():
    mac = [random.randint(0x00, 0xFF) for _ in range(6)]
    return ':'.join(f"{hex_byte:02x}" for hex_byte in mac)

def calc_rates(rates):
    list_rates_transmition = []
    for rate in rates:   
        value_rate = (rate & 0x7f) * 500
        list_rates_transmition.append(value_rate)
    return list_rates_transmition


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
