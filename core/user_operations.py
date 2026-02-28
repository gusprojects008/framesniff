import subprocess
import re
import sys
import time
import json
import socket
import threading
import os
from logging import getLogger
from typing import Optional, Tuple, List
from core.l2.ieee802.dot11.frame import Frame
from core.common.function_utils import (verify_supported_dlts, import_module, new_file_path, check_root, finish_capture, check_interface_mode)
from core.common.parser_utils import (iter_packets_from_json, MacVendorResolver)
from core.common.filter_engine import apply_filters
from core.common.sockets import create_raw_socket

logger = getLogger(__name__)

class Operations:
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
    def scan_station_mode(ifname: str = None, output_filename: str = None):
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
    
        output_filename = str(new_file_path("station-scan-result", ".txt", output_filename))
    
        if result.stdout:
            with open(output_filename, "w") as file:
                file.write(result.stdout)
        
            blocks = result.stdout.strip().split("\nBSS ")
            network_count = 0
            
            for block in blocks[1:]:
                network_count += 1
                _print_network_summary(block, network_count)
            
            logger.info(f"\nTotal networks found: {network_count}")

    @staticmethod
    def sniff(dlt: str = "DLT_IEEE802_11_RADIO", ifname: str = None,
            store_filter: str = None, display_filter: str = None, 
            count: int = None, timeout: float = None, 
            display_interval: float = 0.0, store_callback: callable = None,
            display_callback: callable = None, stop_event: threading.Event = None,
            output_filename: str = None
        ):
    
        check_root()
        check_interface_mode(ifname, "monitor")
    
        mac_vendor_resolver = MacVendorResolver()
        parser = None
    
        if dlt == "DLT_IEEE802_11_RADIO":
            parser = Frame.frames_parser
    
        if parser is None:
            raise ValueError(f"There is no parser available for DLT: {dlt}")
    
        sock = create_raw_socket(ifname)

        output_filename = new_file_path(filename=output_filename) if output_filename else new_file_path(base="framesniff-capture", ext=".json")

        captured_frames = []
        frame_counter = 0
        last_display_time = 0.0
    
        try:
            logger.info(f'''
    Starting capture on {ifname}... (Press Ctrl+C to stop)\n
    Store filter: {store_filter}"\n
    Display filter: {display_filter}\n
    Output path: {output_filename}
    Timeout: {timeout} seconds
            ''')
    
            start_time = time.time()
    
            while True:
                if stop_event and stop_event.is_set():
                    logger.info("Stop event received, finishing capture...")
                    break
                
                if timeout and (time.time() - start_time) >= timeout:
                    logger.info(f"Capture timeout reached after {timeout} seconds")
                    break
                
                try:
                    frame, _ = sock.recvfrom(65535)
                    hex_frame = frame.hex()

                    try:
                        logger.debug(f"Sniff: Parsing frame: {hex_frame}\nframe counter: {frame_counter}") # exc_info=None: None None !?
                        parsed_frame = parser(frame, mac_vendor_resolver)
                    except Exception as e:
                        logger.debug(f"Sniff: parser frame error: {e} ===>\nframe: {hex_frame}\nframe counter: {frame_counter}", exc_info=True)
                        continue
    
                    if not parsed_frame:
                        continue
                    
                    parsed_frame["counter"] = frame_counter
                    parsed_frame["raw"] = hex_frame

                    store_result, display_result = apply_filters(store_filter, display_filter, parsed_frame)
                    
                    if store_result:
                        frame_counter += 1
                        captured_frames.append(parsed_frame)
                        if store_callback:
                            store_callback(parsed_frame)
                    if display_result and display_callback:
                        display_callback(display_result)
                    if display_result and not display_callback:
                        current_time = time.time()
                        if store_result and current_time - last_display_time >= display_interval:
                            try:
                                logger.info(f"[{frame_counter}] {json.dumps(display_result, ensure_ascii=False)}")
                            except Exception:
                                logger.warning(f"[{frame_counter}] {display_result}")
                            last_display_time = current_time
                    if count is not None and frame_counter >= count:
                        break
                        
                except KeyboardInterrupt:
                    logger.info("Capture interrupted by user")
                    break
                except Exception as e:
                    logger.error(f"Error receiving frame: {e}")
                    continue

        except Exception as e:
            logger.critical(f"Unexpected error in sniff: {e}")

        finally:
            logger.info(f"Finishing capture, saving {len(captured_frames)} frames...")
            if stop_event:
                stop_event.set()
            finish_capture(sock, start_time, captured_frames, output_filename)

    @staticmethod
    def set_frequency(ifname: str, frequency_mhz: int, channel: int, channel_width: int = None) -> bool:
        attempts = []
        if channel_width:
            attempts.append(["sudo", "iw", ifname, "set", "freq", str(frequency_mhz), str(channel_width)])
        attempts.append(["sudo", "iw", ifname, "set", "freq", str(frequency_mhz)])
        if channel:
            try:
                attempts.insert(0, ["sudo", "iw", ifname, "set", "channel", str(channel)])
            except Exception as e:
                logger.error(f"Invalid channel value: {channel} ({e})")
                return False
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
        bands,
        channel_width: int = 20,
        dwell: float = 4.0,
        output_filename: str = None
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
            if output_filename:
                output_filename = str(new_file_path(filename=output_filename))
                with open(output_filename, "w", encoding="utf-8") as file:
                    json.dump(config, file, indent=4)
                logger.info(f"Config file saved to: {output_filename}")
            else:
                return config
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
                    ch = int(ch_str)
                    freq = params.get("frequency")
                    dwell = params.get("dwell", 4.0) # seconds
                    width = int(params.get("channel_width", 20))
                    if allowed and ch not in allowed:
                        continue
                    if disallowed and ch in disallowed:
                        continue
                    channels_to_scan.append((ch, freq, band, dwell, width))
                except Exception as e:
                    logger.warning(f"Skipping invalid channel entry '{ch_str}': {e}")
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
            logger.error(traceback.format_exc())
        finally:
            logger.info("Channel hopper finished.")

    @staticmethod
    def generate_22000(bitmask_message_pair: int = 2, ssid: str = None, input_filename: str = None, output_filename: str = "hashcat.22000") -> str:
        Frame.generate_22000(bitmask_message_pair, ssid, input_filename, output_filename)

    @staticmethod
    def write_pcap_from_json(dlt: str, input_filename: str, output_filename: str):
        verify_supported_dlts(dlt)
        import_module("dpkt")
        import dpkt
        linktypes = {
            "DLT_IEEE802_11_RADIO": dpkt.pcap.DLT_IEEE802_11_RADIO,
            "DLT_EN10MB": dpkt.pcap.DLT_EN10MB,
            "DLT_BLUETOOTH_HCI_H4": dpkt.pcap.DLT_BLUETOOTH_HCI_H4,
        }
        output_filename = new_file_path("packets", ".pcap", output_filename)
        with open(output_filename, "wb") as out:
            writer = dpkt.pcap.Writer(out, linktype=linktypes[dlt])
            count = 0
            for hexstr, b in iter_packets_from_json(input_filename):
                writer.writepkt(b, ts=time.time())
                count += 1
                logger.info(f"{count} packet writed: {b[:50]}...")
            writer.close()
            logger.info(f"Output file: {output_filename}")

    @staticmethod
    def send_raw(ifname: str, input_filename: str, count: int = 1, interval: float = 1.0, timeout: float = None):
        sock = create_raw_socket(ifname)
        if timeout is not None:
            sock.settimeout(timeout)
        try:
            for cleaned, raw_bytes in iter_packets_from_json(input_filename):
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
