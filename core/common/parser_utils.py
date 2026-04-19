import json
import re
import binascii
import struct
from logging import getLogger
from functools import lru_cache
from contextvars import ContextVar
from contextlib import contextmanager
from core.layers.l2.ieee802.dot11.constants import *
from core.layers.l2.constants import *

logger = getLogger(__name__)

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
        mac_address = ':'.join(format(byte, "02x") for byte in mac_bytes)
        if not self._vendor_map or not mac_address:
            return None
        oui = mac_address.upper()[:8]
        return {"addr": mac_address, "vendor": self._vendor_map.get(oui)}
    
    def oui_resolver(self, oui_bytes: bytes):
        oui = ':'.join(format(byte, "02x") for byte in oui_bytes)
        if not self._vendor_map or not oui:
            return None
        return {"oui": oui, "vendor": self._vendor_map.get(oui)}

mac_vendor_resolver = MacVendorResolver()

bytes_for_mac = lambda mac : mac_vendor_resolver.mac_resolver(mac)
bytes_for_oui = lambda oui : mac_vendor_resolver.oui_resolver(oui)

def read_mac() -> dict:
    return unpack(f"{EUI48_LENGTH}s", parser=bytes_for_mac)

def read_oui() -> dict:
    return unpack(f"{OUI_LENGTH}s", parser=bytes_for_oui)

def random_mac():
    mac = [random.randint(0x00, 0xFF) for _ in range(6)]
    return ':'.join(f"{hex_byte:02x}" for hex_byte in mac)

mac_for_bytes = lambda mac : bytes(int(hex_byte, 16) for hex_byte in mac.split(":"))

_parse_context = ContextVar("_parse_context")
class ParseContext:
    def __init__(self, frame: bytes, start_offset: int = 0):
        self.frame = frame
        self.offset = start_offset
        self.result = {}
        self._token = None

    def __enter__(self):
        self._token = _parse_context.set(self)
        return self

    def __exit__(self, *args):
        _parse_context.reset(self._token)

    @staticmethod
    def current():
        return _parse_context.get(None)

    def set(self, key, value):
        self.result[key] = value

    def get(self, key, default=None):
        return self.result.get(key, default)

    def update(self, data):
        self.result.update(data)

def find_path(root, target, path=None):
    if path is None:
        path = []

    if root is target:
        return path

    if isinstance(root, dict):
        for k, v in root.items():
            res = find_path(v, target, path + [k])
            if res:
                return res

    elif isinstance(root, list):
        for i, v in enumerate(root):
            res = find_path(v, target, path + [str(i)])
            if res:
                return res

    return None

def clean_path(path):
    return ".".join([p for p in path if p != "parsed"])

def size_to_struct_fmt(size: int) -> str:
    mapping = {
        1: "B",
        2: "H",
        4: "I",
        8: "Q"
    }
    if size not in mapping:
        raise ValueError(f"Unsupported struct size: {size}")
    return mapping[size]

@lru_cache(maxsize=256)
def _parse_fmt_tokens(fmt: str) -> tuple[tuple[int, ...], tuple[str, ...]]:
    s = struct.Struct(fmt)

    prefix = '<'
    if fmt and fmt[0] in '<>!=@':
        prefix = fmt[0]
        fmt = fmt[1:]

    tokens: list[str] = []
    count_buf = ''

    for ch in fmt:
        if ch.isdigit():
            count_buf += ch
        else:
            count = int(count_buf) if count_buf else 1
            if ch in ('s', 'p'):
                tokens.append(f"{prefix}{count}{ch}")
            else:
                tokens.extend([prefix + ch] * count)
            count_buf = ''

    if count_buf:
        raise ValueError(f"Invalid format: ends with count without type '{count_buf}'")

    sizes = tuple(struct.calcsize(t) for t in tokens)

    sizes = sizes[0] if len(sizes) == 1 else sizes
    tokens = tokens[0] if len(tokens) == 1 else tokens

    return sizes, tuple(tokens), s

def _add_metadata(raw: bytes, start_offset: int, end_offset: int, fmt: str | dict, tokens: str | dict, sizes: int | dict, size: int):
    raw_hex = raw[start_offset:end_offset].hex()
    length = end_offset - start_offset
    return {
        "_metadata_": {
            "start": start_offset,
            "end": end_offset,
            "length": length,
            "raw": raw_hex,
            "fmt": fmt,
            "tokens": tokens,
            "sizes": sizes,
            "size": size
        }
    }

#def unpack(fmt: str = None, parser: callable = None, descriptor: str | callable = None, **kwargs) -> dict:
def unpack(fmt: str = None, parser: callable = None, **kwargs) -> dict:
    def value_to_dict(value):
        return {i: v for i, v in enumerate(value)} if isinstance(value, tuple) else value

    result = {}

    ctx = ParseContext.current()
    raw = ctx.frame
    offset = ctx.offset
    start = offset
    fmt = (fmt or f"{len(raw) - start}s").replace(" ", "")
    sizes, tokens, s = _parse_fmt_tokens(fmt)
    size = s.size

    fmt = value_to_dict(fmt)
    sizes = value_to_dict(sizes)
    tokens = value_to_dict(tokens)
    future_offset = start + size
    result.update(_add_metadata(raw, start, future_offset, fmt, tokens, sizes, size))

    if offset + size > len(raw):
        logger.debug(f"Truncated raw: start_offset={offset} fmt={fmt} sizes={sizes} size={size}")
        return fail(result, future_offset, "Unpack error truncated")

    value = s.unpack_from(raw, offset)

    value = value[0] if len(value) == 1 else value

    ctx.offset = future_offset

    result["value"] = value_to_dict(value)

    if parser:
        parser_result = parser(value, **kwargs)
        result["parsed"] = parser_result
        #result["description"] = descriptor(parser_result, **kwargs) if callable(descriptor) else descriptor

    return result

def run_dispatch(dispatch_table: dict, dispatch_id, fallback: callable = None, **kwargs):
    logger.debug(f"run dispatch")

    entry = dispatch_table.get(dispatch_id)

    dispatch_ctx = {
        "dispatch_id": dispatch_id,
        "dispatch_table": dispatch_table,
        "dispatch_fallback": fallback,
        "dispatch_entry": entry
    }

    kwargs["dispatch_ctx"] = dispatch_ctx

    handler = None

    if callable(entry):
        handler = entry

    elif isinstance(entry, dict):
        handler = entry.get("parser")

    if handler:
        return handler(**kwargs)

    if fallback:
        return fallback(**kwargs)

    logger.debug(f"No handler for dispatch_id={dispatch_id}, using unpack fallback")

    return unpack(**kwargs)

def detect_fcs(**kwargs) -> bytes | None:
    logger.debug("detect_fcs function")
    ctx = ParseContext.current()
    frame = ctx.frame
    offset = ctx.offset
    flen = len(frame)
    logger.debug(f"detect_fcs function: frame:{frame} offset={offset} flen={flen}")

    if offset is None or offset < 0 or offset >= flen:
        return None

    payload_len = flen - offset
    if payload_len < IEEE80211_FCS_LEN:
        return None

    fcs_start = flen - IEEE80211_FCS_LEN
    fcs_bytes = frame[fcs_start:flen]
    candidate_fcs = int.from_bytes(fcs_bytes, "little")
    data_for_crc = frame[offset:fcs_start]
    calc_crc = binascii.crc32(data_for_crc) & 0xFFFFFFFF

    if calc_crc == candidate_fcs:
        ctx.frame = frame[:fcs_start]
        return fcs_bytes.hex()
    else:
        return None

def insert_item(container: dict, key: str | int, val: dict | str | int):
    if key not in container:
        container[key] = val
        return
    if not isinstance(container[key], dict) or not all(k.isdigit() for k in container[key]):
        container[key] = {"1": container[key]}
    idx = str(len(container[key]) + 1)
    container[key][idx] = val

def fail(result: dict, expected_size: int, e: str = "Parser error", debug_msg: str = "Parse error"):
    logger.debug("fail function")
    ctx = ParseContext.current()
    insert_item(result, "_fail_", e)
    frame_len = len(ctx.frame)
    if expected_size is not None:
        ctx.offset = min(expected_size, frame_len)
    logger.debug(f"{debug_msg} frame_len={frame_len} ctx.offset={ctx.offset} expected_size={expected_size} result={result}")
    return result

def bitmap_dict_to_hex(bitmap_dict: dict):
    result = 0
    for i, (field, active) in enumerate(bitmap_dict.items()):
        if active:
            result |= (1 << i)
    return result

def bitmap_value_for_dict(bitmap_value: int, field_names: list[str]) -> dict:
    result = {}
    for i, name in enumerate(field_names):
        result[name] = bool(bitmap_value & (1 << i))
    return result

def clean_hex_string(s: str) -> str:
    s = s.strip().strip("'").strip('"')
    return re.sub(r'[^0-9a-fA-F]', '', s).lower()

def bytes_encoder(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Type {type(obj)} not serializable")

def normalize_bytes(obj):
    if isinstance(obj, dict):
        return {k: normalize_bytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [normalize_bytes(v) for v in obj]
    elif isinstance(obj, bytes):
        return obj.hex()
    return obj

def calc_offset_from_fmt(tokens: dict, field_index: int) -> int:
    offset = 0
    for i in range(field_index):
        offset += struct.calcsize(tokens[i])
    return offset

def clear_field(raw: bytes, metadata: dict, field_index: int, field_length: int) -> bytes:
    tokens = metadata["tokens"]
    offset = calc_offset_from_fmt(tokens, field_index)
    buffer = bytearray(raw)
    buffer[offset : offset + field_length] = b"\x00" * field_length
    return bytes(buffer)

def iter_packets_from_json(path: str):
    key = "raw"

    def _extract_values(data_obj):
        if isinstance(data_obj, dict):
            value = data_obj.get(key)
            if isinstance(value, str):
                cleaned = clean_hex_string(value)
                if cleaned:
                    yield (cleaned, bytes.fromhex(cleaned))
            elif isinstance(value, list):
                for entry in value:
                    if isinstance(entry, str):
                        cleaned = clean_hex_string(entry)
                        if cleaned:
                            yield (cleaned, bytes.fromhex(cleaned))
        elif isinstance(data_obj, list):
            for item in data_obj:
                yield from _extract_values(item)

    is_jsonl = str(path).lower().endswith(".jsonl")

    try:
        with open(path, "r", encoding="utf-8") as file:
            if is_jsonl:
                for line_num, line in enumerate(file, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        yield from _extract_values(data)
                    except json.JSONDecodeError as error:
                        raise ValueError(f"Erro decodificando JSONL na linha {line_num}: {error}")
            else:
                content = file.read()
                try:
                    data = json.loads(content)
                    yield from _extract_values(data)
                except json.JSONDecodeError as original_error:
                    decoder = json.JSONDecoder()
                    idx = 0
                    length = len(content)
                    parsed_at_least_one = False

                    while idx < length:
                        while idx < length and content[idx].isspace():
                            idx += 1
                        if idx >= length:
                            break

                        try:
                            data, idx = decoder.raw_decode(content, idx)
                            yield from _extract_values(data)
                            parsed_at_least_one = True
                        except json.JSONDecodeError:
                            break

                    if not parsed_at_least_one:
                        raise ValueError(f"Error trying to load json file: {original_error}")

    except Exception as error:
        raise RuntimeError(f"Could not open or process file {path}: {error}")

wireshark_format = lambda packet_bytes : ":".join(f"{byte:02x}" for byte in packet_bytes)

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
        raise ValueError(f"Invalid source unit: {unit} Use 'kHz', 'MHz' ou 'GHz'")
    
    if to_unit == 'khz':
       return base_freq
    elif to_unit == 'mhz':
         return base_freq / 1000
    elif to_unit == 'ghz':
         return base_freq / 1000000
    else:
        raise ValueError(f"Destiny unit invalid: {to_unit}. Use 'kHz', 'MHz' ou 'GHz'")

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

def calc_rates(rates):
    list_rates_transmition = []
    for rate in rates:   
        value_rate = (rate & 0x7f) * 500
        list_rates_transmition.append(value_rate)
    return list_rates_transmition
