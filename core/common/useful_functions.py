import struct
import random
import socket
import sys
import re
import json
import time
import binascii
import os
import subprocess
from typing import Tuple, Optional
from pathlib import Path

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

def new_file_path(base: str = None, ext: str = None, filename: str = None) -> Path:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    if not filename:
        if base and ext:
            return Path(f"{base}-{timestamp}{ext}")
        elif base:
            return Path(f"{base}-{timestamp}")
        else:
            return Path(f"{timestamp}")
    else:
        return Path(f"{timestamp}-{filename}")

# returns the hexadecimal contents of a dictionary of a bitmap.
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

def safe_unpack(fmt: str, frame: bytes, offset: int):
    size = struct.calcsize(fmt)
    if offset + size > len(frame):
        return None, offset
    return struct.unpack_from(fmt, frame, offset), offset + size

def unpack(fmt, frame, off):
    res, new_off = safe_unpack(fmt, frame, off)
    if res is None:
        return None, off
    return res[0], new_off

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
            print(f"INFO: Loading MAC vendors file {filepath} ...")
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    MacVendorResolver._vendor_map = {
                        item['macPrefix']: item['vendorName'] for item in data
                    }
                print("INFO: MAC vendors loaded successfully.")
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"ERROR: Could not load or parse MAC vendors file: {e}")
                MacVendorResolver._vendor_map = {}

    def mac_resolver(self, mac_bytes: bytes):
        if not mac_bytes:
            return None
        mac_address = bytes_for_mac(mac_bytes)
        if not self._vendor_map or not mac_address:
            return None
        oui = mac_address.upper()[:8]
        return {"mac": mac_address, "vendor": self._vendor_map.get(oui, "Unknown")}

def finish_capture(sock, start_time: int, captured_frames: list, output_file_path: str):
    sock.close()
    capture_duration = time.time() - start_time
    print(f"DEBUG: Finish capture called with {len(captured_frames)} frames")  # DEBUG
    print(f"DEBUG: Output path: {output_file_path}")  # DEBUG
    if captured_frames:
        try:
            with open(output_file_path, "w") as file:
                json.dump(captured_frames, file, indent=2)
            print(f"Captured {len(captured_frames)} frames in {capture_duration:.2f}s")
            print(f"Saved to: {output_file_path}")
        except Exception as e:
            print(f"Error saving file: {e}")
    else:
        print("No frames captured")

def import_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        raise ImportError(f'''
    Error when trying to import {module_name}, run the following commands:\n
    python -m venv venv
    source venv/bin/activate
    pip install {module_name}
    python {' '.join(sys.argv)}
''')

def check_root():
    if os.geteuid() != 0:
       raise PermissionError(f"This program requires root permissions to run.\nRun: sudo {' '.join(sys.argv)}")

def check_interface_mode(ifname: str, mode: str) -> bool:
    try:
        result = subprocess.run(['iw', 'dev', ifname, 'info'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Interface {ifname} not found or iw command failed")
        match = re.search(r'type\s+(\w+)', result.stdout)
        if match:
            if match.group(1).lower() == mode:
               return True
            else:
                raise Exception(f"error, set the interface to {mode}:\n RUN: sudo framesniff.py set-{mode} -i {ifname}")
        raise RuntimeError(f"Could not determine interface type for {ifname}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("iw command timed out")
    except FileNotFoundError:
        raise RuntimeError("iw command not found")
    except Exception as error:
        raise RuntimeError(f"Error checking interface mode: {error}")

def verify_supported_dlts(dlt: str = None):
    linktypes = [
        "DLT_IEEE802_11_RADIO",
        "DLT_EN10MB",
        "DLT_BLUETOOTH_HCI_H4"
    ]
    if dlt not in linktypes:
        raise ValueError(f"Unsupported DLT: {dlt}\n{', '.join(linktypes)}")

def export_tui_for_txt(app, output_filename: str = None):
    out_path = str(new_file_path(filename=output_filename))
    try:
        snapshot_lines = []
        def extract_table_data(table_widget):
            try:
                if hasattr(table_widget, 'data') and hasattr(table_widget, 'columns'):
                    rows = []
                    headers = []
                    for col in table_widget.columns:
                        if hasattr(col, 'label'):
                            headers.append(str(col.label))
                        elif hasattr(col, 'header'):
                            headers.append(str(col.header))
                        else:
                            headers.append(str(col))
                    rows.append(" | ".join(headers))
                    if hasattr(table_widget, 'get_row'):
                        for row_key in table_widget.rows:
                            row_data = table_widget.get_row(row_key)
                            if row_data:
                                row_str = " | ".join(str(cell) for cell in row_data)
                                rows.append(row_str)
                    return "\n".join(rows)
                return None
            except Exception as e:
                print(f"Table extraction error: {e}")
                return None
        
        def extract_text_from_widget(widget):
            try:
                if hasattr(widget, '__class__') and 'DataTable' in str(widget.__class__):
                    return extract_table_data(widget)
                if hasattr(widget, 'value'):
                    text = str(widget.value)
                    if text.strip():
                        return text
                if hasattr(widget, 'renderable'):
                    renderable = widget.renderable
                    if renderable is not None:
                        text = str(renderable)
                        if text.strip():
                            return text.strip()
                if hasattr(widget, '_text'):
                    text = str(widget._text)
                    if text.strip():
                        return text.strip()
                if hasattr(widget, 'render') and callable(widget.render):
                    try:
                        rendered = widget.render()
                        if rendered is not None:
                            text = str(rendered)
                            if text.strip():
                                return text.strip()
                    except:
                        pass
                return None
            except Exception:
                return None
        for widget in app.walk_children():
            try:
                text_content = extract_text_from_widget(widget)
                if text_content:
                    snapshot_lines.append(text_content)
            except Exception:
                continue
        if not snapshot_lines:
            snapshot_lines = extract_fallback_data(app)
        snapshot = "\n".join(snapshot_lines)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(snapshot)
        print(f"[SUCCESS] TUI content exported to: {out_path}")
        return out_path
    except Exception as error:
        print(f"[ERROR] Failed to export TUI content: {error}")
        return None
