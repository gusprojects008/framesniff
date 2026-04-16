import subprocess
import re
import sys
import time
import json
import socket
import threading
import struct
import os
from logging import getLogger
from typing import Optional, Tuple, List
from core.common.function_utils import (verify_supported_dlts, import_module, new_file_path, check_root, check_interface_mode)
from core.common.parser_utils import iter_packets_from_json, bytes_encoder, normalize_bytes, clear_field
from core.common.filter_engine import apply_filters
from core.common.sockets import create_raw_socket
from core.common.constants.hashcat import *
from core.layers.l2.ieee802.dot1x.constants import *
from core.layers.registry import (get_parser, get_dlt_value)
import dpkt

logger = getLogger(__name__)

class Hashcat:
    @staticmethod
    def _build_eapol_line(ssid: str, input_fullpath: str):
        eapol_msg1_hex = None
        eapol_msg2_hex = None
    
        for i, (hexstr, _) in enumerate(iter_packets_from_json(input_fullpath)):
            if i == 0:
                eapol_msg1_hex = hexstr
            elif i == 1:
                eapol_msg2_hex = hexstr
                break
    
        if not eapol_msg1_hex or not eapol_msg2_hex:
            raise ValueError("Need at least 2 EAPOL frames")
    
        parser = get_parser("DLT_IEEE802_11_RADIO")
    
        msg1 = parser(bytes.fromhex(eapol_msg1_hex))
        msg2 = parser(bytes.fromhex(eapol_msg2_hex))
    
        msg2_mac = msg2["mac_hdr"]["parsed"]
    
        ap_mac = msg2_mac["bssid"]["value"].hex()
        sta_mac = (msg2_mac["sa"]["value"] or msg2_mac["ta"]["value"]).hex()
    
        msg1_eapol = msg1["body"]["llc"]["parsed"]["payload"]
        msg2_eapol = msg2["body"]["llc"]["parsed"]["payload"]
    
        anonce = msg1_eapol.get("parsed").get("key_nonce").hex()
        mic = msg2_eapol.get("parsed").get("key_mic").hex()
    
        if not all([ap_mac, sta_mac, anonce, mic]):
            raise ValueError("Missing EAPOL data")
    
        payload_meta = msg2_eapol.get("_metadata_")
      
        fields = list(msg2_eapol.get("parsed").keys())

        try:
            mic_index = fields.index("key_mic")
        except ValueError:
            raise ValueError("'key_mic' not found in EAPOL")
      
        eapol_zero_mic = clear_field(payload_meta, mic_index, EAPOL_KEY_MIC_LENGTH)

        return f"WPA*02*{mic}*{ap_mac}*{sta_mac}*{ssid}*{anonce}*{eapol_zero_mic}*00"

    @staticmethod
    def _build_pmkid_line(ssid: str, input_fullpath: str):
        with open(input_fullpath, "r", encoding="utf-8") as f:
            data = json.load(f)
            pmkid = clean_hex_string(data.get("pmkid"))
            ap_mac = clean_hex_string(data.get("ap_mac"))
            sta_mac = clean_hex_string(data.get("sta_mac"))
            if not all([pmkid, ap_mac, sta_mac]):
                raise ValueError("Missing PMKID data")
            return f"WPA*01*{pmkid}*{ap_mac}*{sta_mac}*{ssid}***00"

    GENERATORS = {
        WPA_PBKDF2_PMKID_EAPOL: "_generate_22000"
    }

    @classmethod
    def generate(cls, hformat, **kwargs):
        generator_name = cls.GENERATORS.get(hformat)

        if not generator_name:
            raise ValueError(f"Unsupported hashcat format: {hformat}")

        generator = getattr(cls, generator_name)
        return generator(**kwargs)

    @staticmethod
    def _generate_22000(bitmask: int, ssid: str, input_fullpath: str):
        if not input_fullpath:
            raise ValueError("Input file must be provided.")

        if not ssid:
            raise ValueError("SSID must be provided.")

        ssid = ssid.encode().hex()

        if bitmask == MESSAGE_PAIR_M1_M4:
            return Hashcat._build_pmkid_line(ssid, input_fullpath)

        elif bitmask == MESSAGE_PAIR_M1_M2:
            return Hashcat._build_eapol_line(ssid, input_fullpath)

        else:
            raise ValueError("Unsupported bitmask")

class Operations:
    @staticmethod
    def sniff(
            dlt: str = "DLT_IEEE802_11_RADIO",
            ifname: str = None,
            store_filter: str = None,
            display_filter: str = None,
            count: int = None,
            timeout: float = None,
            display_interval: float = 0.0,
            store_callback: callable = None,
            display_callback: callable = None,
            stop_event: threading.Event = None,
            simple_output: bool = False,
            output_fullpath: str = None,
        ):
            check_root()
            check_interface_mode(ifname, "monitor")
        
            try:
                parser = get_parser(dlt)
            except ValueError as e:
                logger.error(e)
                return
        
            sock = create_raw_socket(ifname)
            output_fullpath = new_file_path(output_fullpath, "framesniff-capture.json")
            frame_counter = 0
            last_display_time = 0.0
            start_time = time.time()

            try:
                logger.info(
                    f"Starting capture on {ifname}... (Press Ctrl+C to stop)\n"
                    f"Store filter: {store_filter}\n"
                    f"Display filter: {display_filter}\n"
                    f"Output path: {output_fullpath}\n"
                    f"Timeout: {timeout} seconds"
                )
        
                with open(output_fullpath, "a") as f:
                    while True:    
                        if stop_event and stop_event.is_set():
                            logger.info("Stop event received, finishing...")
                            break
        
                        if timeout and (time.time() - start_time) >= timeout:
                            logger.info(f"Timeout of {timeout}s reached.")
                            break
        
                        try:
                            frame, _ = sock.recvfrom(65535)
                            frame_hex = frame.hex()
        
                            try:
                                parsed_frame = parser(frame)
                            except Exception as e:
                                logger.debug(
                                    f"Sniff: parser frame error: {e}\nframe: {hex_frame}\nframe counter: {frame_counter}",
                                    exc_info=True,
                                )
                                continue
        
                            parsed_frame["counter"] = frame_counter
                            parsed_frame["raw"] = frame_hex
                            
                            store_result, display_result = apply_filters(store_filter, display_filter, parsed_frame)
        
                            if store_result:
                                if simple_output:
                                    dump = json.dumps(parsed_frame, default=bytes_encoder, separators=(",", ":"))
                                else:
                                    dump = json.dumps(parsed_frame, default=bytes_encoder, indent=2)
        
                                f.write(dump + "\n")
                                
                                if frame_counter % 100 == 0:
                                    f.flush()
        
                                frame_counter += 1

                                if store_callback:
                                    store_callback(parsed_frame)
        
                            if display_result:
                                if display_callback:
                                    display_callback(display_result)
                                else:
                                    current_time = time.time()
                                    if current_time - last_display_time >= display_interval:
                                        try:
                                            log_out = json.dumps(display_result, default=bytes_encoder, ensure_ascii=False)
                                            logger.info(f"[{frame_counter}] {log_out}")
                                        except Exception as log_err:
                                            logger.warning(f"[{frame_counter}] {display_result}")
                                        
                                        last_display_time = current_time
        
                            if count is not None and frame_counter >= count:
                                break
                        except KeyboardInterrupt:
                            logger.info("Capture interrupted by user")
                            break
                        except Exception as e:
                            logger.error(f"Error processing frame: {e}")
                            continue
            except Exception as e:
                logger.critical(f"Unexpected error in sniff: {e}")
        
            finally:
                logger.info(f"Finishing capture, saving {frame_counter} frames...")
                sock.close()
                if stop_event:
                    stop_event.set()

    @staticmethod
    def generate_hashcat(hformat, **kwargs):
        return Hashcat.generate(hformat, **kwargs)

    @staticmethod
    def write_pcap_from_json(dlt: str, input_fullpath: str, output_fullpath: str):
        linktype = get_dlt_value(dlt) 
        output_fullpath = new_file_path(output_fullpath, "packets.pcap")
        with open(output_fullpath, "wb") as out:
            writer = dpkt.pcap.Writer(out, linktype=linktype)
            count = 0
            for hexstr, b in iter_packets_from_json(input_fullpath):
                writer.writepkt(b, ts=time.time())
                count += 1
                logger.info(f"{count} packet writed: {b[:50]}...")
            writer.close()
            logger.info(f"Output file: {output_fullpath}")

    @staticmethod
    def send_raw(ifname: str, input_fullpath: str, count: int = 1, interval: float = 1.0, timeout: float = None):
        sock = create_raw_socket(ifname)
        if timeout is not None:
            sock.settimeout(timeout)
        try:
            for cleaned, raw_bytes in iter_packets_from_json(input_fullpath):
                for i in range(count):
                    try:
                        bytes_sent = sock.send(raw_bytes)
                        logger.info(f"Frame sent ({i+1}/{count}): {bytes_sent} bytes")
                        if i < count - 1:
                            time.sleep(interval)
                    except socket.error as e:
                        logger.error(f"Failed to send frame: {e}")
                        break
                    except Exception as e:
                        logger.critical(f"Unexpected error: {e}")
                        break
        finally:
            sock.close()

    @staticmethod
    def scan_monitor(ifname, dlt, channel_hopping, channel_hopping_interval, timeout):
        from core.tui.scan_monitor import scan_monitor
        logger.info("press ctrl+s or <F12> to save tui information!")
        scan_monitor(ifname=ifname, dlt=dlt, channel_hopping=channel_hopping, channel_hopping_interval=channel_hopping_interval, timeout=timeout, Operations=Operations)

    @staticmethod
    def list_network_interfaces() -> str:
        logger.info(" In development, see https://github.com/gusprojects008/wnlpy")
        result = subprocess.run(
            ["iw", "dev"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        return result.stdout.strip()

    @staticmethod
    def list_network_interface(ifname: str) -> str:
        logger.info(" In development, see https://github.com/gusprojects008/wnlpy")
        result = subprocess.run(
            ["iw", "dev", ifname, "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        return result.stdout.strip()

    @staticmethod
    def set_monitor(ifname: str):
        logger.info(" In development, see https://github.com/gusprojects008/wnlpy")
        try:
            subprocess.run(["sudo", "ip", "link", "set", ifname, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            subprocess.run(["sudo", "iw", "dev", ifname, "set", "type", "monitor"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            subprocess.run(["sudo", "ip", "link", "set", ifname, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            logger.info(f"{ifname} configured for monitor mode!")
        except Exception as e:
            logger.error(f"error configure {ifname} to monitor mode: {e}")

    @staticmethod
    def set_station(ifname: str):
        logger.info(" In development, see https://github.com/gusprojects008/wnlpy")
        try:
            subprocess.run(["sudo", "ip", "link", "set", ifname, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            subprocess.run(["sudo", "iw", "dev", ifname, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            subprocess.run(["sudo", "ip", "link", "set", ifname, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            logger.info(f"{ifname} configured for station/management mode!")
        except Exception as e:
            logger.error(f"error configure {ifname} to station mode: {e}")

    @staticmethod
    def scan_station_mode(ifname: str = None, output_fullpath: str = None):
        logger.info(" In development, see https://github.com/gusprojects008/wnlpy\n")
    
        logger.info(f" Scanning WiFi networks on {ifname}...\n")
        
        try:
            result = subprocess.run(
                ["sudo", "iw", "dev", ifname, "scan"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            logger.critical(f"Error during scan: {e}")
            return
        except FileNotFoundError:
            logger.error("Error: 'iw' command not found. Please install wireless tools.")
            return
    
        def _extract_value(block: str, pattern: str) -> str:
            match = re.search(pattern, block)
            return match.group(1) if match else "N/A"
    
        def _get_security_type(block: str) -> str:
            if "WPA3" in block or "SAE" in block:
                return "WPA3"
            elif "WPA2" in block or "RSN:" in block:
                return "WPA2"
            elif "WPA:" in block:
                return "WPA"
            elif "privacy" in block:
                return "WEP"
            else:
                return "OPEN"
    
        def _get_wps_status(block: str) -> str:
            if "WPS:" not in block:
                return "Disabled"
            status = "Enabled"
            state_match = re.search(r"Wi-Fi Protected Setup State:\s*(\d+)\s*\((\w+)\)", block)
            if state_match:
                status += f" ({state_match.group(2)})"
            methods_match = re.search(r"Config methods:\s*(.+)", block)
            if methods_match:
                status += f" - {methods_match.group(1)}"
            if "AP setup locked: 0x01" in block:
                status += " [LOCKED]"
            return status
    
        def _print_network_summary(block: str, num: int):
            bssid = _extract_value(block, r"^([0-9a-f:]{17})")
            ssid = _extract_value(block, r"SSID:\s*(.+)") or "Hidden"
            signal = _extract_value(block, r"signal:\s*([-\d.]+)\s*dBm")
            channel = _extract_value(block, r"DS Parameter set:\s*channel\s*(\d+)")
            frequency = _extract_value(block, r"freq:\s*([\d.]+)")
            
            security = _get_security_type(block)
            wps_info = _get_wps_status(block)
            vendor = _extract_value(block, r"Manufacturer:\s*(.+)")
            
            encryption = []
            if "CCMP" in block: encryption.append("AES")
            if "TKIP" in block: encryption.append("TKIP")
            
            print(
                f"┌─── NETWORK #{num} {'─' * 50}\n"
                f"│ SSID: {ssid}\n"
                f"│ BSSID: {bssid}\n"
                f"│ Signal: {signal} dBm | Channel: {channel} | Freq: {frequency} MHz\n"
                f"│ Security: {security}"
            )
            
            if encryption:
                print(f"│ Encryption: {', '.join(encryption)}")
            
            if vendor and vendor != "Unknown":
                print(f"│ Vendor: {vendor}")
            
            print(f"│ WPS: {wps_info}")
            
            flags = []
            if "WPA3" in block or "SAE" in block: flags.append("WPA3")
            if "Management frame protection: required" in block: flags.append("PMF-Required")
            elif "Management frame protection: capable" in block: flags.append("PMF-Capable")
            
            if flags:
                print(f"│ Security Flags: {', '.join(flags)}")
            
            print(f"└{'─' * 60}")
    
        output_fullpath = str(new_file_path(output_fullpath, "station-scan-result.txt"))
    
        if result.stdout:
            with open(output_fullpath, "w") as file:
                file.write(result.stdout)
        
            blocks = result.stdout.strip().split("\nBSS ")
            network_count = 0
            
            for block in blocks[1:]:
                network_count += 1
                _print_network_summary(block, network_count)
            
            logger.info(f"\nTotal networks found: {network_count}")

    @staticmethod
    def set_frequency(ifname: str, frequency_mhz: int = None, channel: int = None, channel_width: int = None) -> bool:
        attempts = []
    
        if channel is not None:
            attempts.append(["iw", ifname, "set", "channel", str(channel)])
    
        elif frequency_mhz is not None:
            if channel_width:
                attempts.append(["iw", ifname, "set", "freq", str(frequency_mhz), str(channel_width)])
            attempts.append(["iw", ifname, "set", "freq", str(frequency_mhz)])
    
        last_err = None
    
        for cmd in attempts:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != 0:
                    last_err = f"{' '.join(cmd)} -> returncode {proc.returncode} stderr:{proc.stderr.strip()}"
                    logger.error(last_err)
                    continue
                return True
            except Exception as e:
                last_err = f"Unexpected error running {' '.join(cmd)}: {e}"
                logger.error(last_err)
    
        return False

    @staticmethod
    def get_channels(bands: list[int | float] = [2.4]) -> dict:
        channel_map = {}
        normalized_bands = []
        for b in bands:
            try:
                if b > 1000:
                    b = round(b / 1000, 1)
                normalized_bands.append(b)
            except Exception as e:
                logger.warning(f"Ignoring invalid band value {b}: {e}")
        if 2.4 in normalized_bands:
            channel_map[2.4] = [(ch, 2407 + ch * 5) for ch in range(1, 14)]
        if 5 in normalized_bands:
            channel_map[5] = [
                (36, 5180), (40, 5200), (44, 5220), (48, 5240),
                (52, 5260), (56, 5280), (60, 5300), (64, 5320),
                (100, 5500), (104, 5520), (108, 5540), (112, 5560),
                (116, 5580), (120, 5600), (124, 5620), (128, 5640),
                (132, 5660), (136, 5680), (140, 5700), (144, 5720),
                (149, 5745), (153, 5765), (157, 5785), (161, 5805), (165, 5825)
            ]
        if 6 in normalized_bands:
            base_freq = 5955
            channel_map[6] = [(ch, base_freq + 5 * (ch - 1)) for ch in range(1, 234)]
        return channel_map

    @staticmethod
    def generate_channel_hopping_config(
        bands: list[float] = [2.4],
        channel_width: int = 20,
        dwell: int | float = 4.0,
        output_fullpath: str = None
    ) -> dict:
        try:
            logger.info(f"Generating channel hopping config for bands {bands} (dwell={dwell}s)...")
            channel_map = Operations.get_channels(bands)
            config = {}
            for band, entries in channel_map.items():
                config[str(band)] = {}
                for ch, freq in entries:
                    config[str(band)][str(ch)] = {
                        "frequency": freq,
                        "dwell": dwell,
                        "channel_width": channel_width
                    }
            output_fullpath = str(new_file_path(output_fullpath, "channel-hopping-config.json"))
            with open(output_fullpath, "w", encoding="utf-8") as file:
                json.dump(config, file, indent=4)
            logger.info(f"Config file saved to: {output_fullpath}")
        except Exception as e:
            logger.error(f"Failed to generate channel hopping config: {e}")
            return {}

    @staticmethod
    def channel_hopper(
        ifname: str,
        channel_hopping_config_path: str = None,
        channel_hopping_config: dict = None,
        allowed: list[int] = None,
        disallowed: list[int] = None,
        callback: callable = None,
        stop_event=None,
        timeout: float = None,
    ):
        config = None
        if channel_hopping_config_path:
            try:
                with open(channel_hopping_config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load channel hopping config: {e}")
                return
        elif channel_hopping_config:
            config = channel_hopping_config
        else:
            logger.error("Either 'channel_hopping_config_path' or 'channel_hopping_config' must be provided.")
            return
        channels_to_scan: list[tuple[int, int, float, int, int]] = []
        for band_str, channels in config.items():
            try:
                band = float(band_str)
            except Exception as e:
                logger.warning(f"Ignoring invalid band key '{band_str}': {e}")
                continue
            for ch_str, params in channels.items():
                try:
                    if not isinstance(params, dict):
                        raise ValueError(f"Invalid params type: {type(params)}")
            
                    ch = int(ch_str)
            
                    freq = params.get("frequency")
                    if freq is None:
                        raise ValueError("Missing frequency")
            
                    dwell = params.get("dwell", 5.0)
                    if dwell is None:
                        dwell = 5.0
            
                    width_val = params.get("channel_width", 20)
                    width = int(width_val) if width_val is not None else 20
            
                    logger.debug(f"Parsed channel: ch={ch}, allowed={allowed}, disallowed={disallowed}")
            
                    if allowed and ch not in allowed:
                        continue
            
                    if disallowed and ch in disallowed:
                        continue
            
                    channels_to_scan.append((ch, freq, band, dwell, width))
            
                except Exception as e:
                    logger.warning(
                        f"Skipping invalid channel entry '{ch_str}' (params={params}): {e}"
                    )
        if not channels_to_scan:
            logger.warning("No valid channels to scan.")
            return
        idx = 0
        start_time = time.time()
        try:
            while True:
                if timeout is not None and (time.time() - start_time) >= timeout:
                    logger.info(f"Channel hopping timed out after {timeout} seconds.")
                    break
                if stop_event and stop_event.is_set():
                    logger.info("Stop event detected, stopping channel hopper.")
                    break
                ch, freq, band, dwell, width = channels_to_scan[idx]
                success = Operations.set_frequency(ifname, freq, channel=ch, channel_width=width)
                if success:
                    logger.info(
                        f"Channel set -> ch={ch} freq={freq}MHz band={band}GHz width={width} dwell={dwell}s"
                    )
                else:
                    logger.error(f"Failed to set channel {ch} ({freq}MHz)")
                if callback:
                    try:
                        callback(channel=ch, band=band)
                    except Exception as e:
                        logger.error(f"Channel hopper callback error: {e}")
                idx = (idx + 1) % len(channels_to_scan)
                time.sleep(dwell)
        except KeyboardInterrupt:
            logger.info("Channel hopping interrupted by user.")
        except Exception as e:
            logger.error(f"Unexpected error in channel hopper: {e}")
        finally:
            logger.info("Channel hopper finished.")
