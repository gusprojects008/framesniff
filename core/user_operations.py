import subprocess
import re
import sys
import time
import json
import socket
import threading
import queue
import traceback
import asyncio
import shlex
import traceback
import os
import logging
from typing import Optional, Tuple, List
from core.wifi.l2.ieee802_11.ieee802_11 import IEEE802_11
from core.common.useful_functions import (import_module, new_file_path, iter_packets_from_json, MacVendorResolver, check_root, finish_capture)
from core.common.filter_engine import apply_filters
from core.common.sockets import create_raw_socket

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("network_scanner.log"), logging.StreamHandler()]
)

file_handler = logging.FileHandler("network_scanner.log")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

logging.basicConfig(level=logging.INFO, handlers=[file_handler])

class Operations:
    @staticmethod
    def list_network_interfaces() -> str:
        print(" In development, see https://github.com/gusprojects008/wnlpy")
        result = subprocess.run(
            ["sudo", "iw", "dev"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        return result.stdout.strip()

    @staticmethod
    def list_network_interface(ifname: str) -> str:
        print(" In development, see https://github.com/gusprojects008/wnlpy")
        result = subprocess.run(
            ["sudo", "iw", "dev", ifname, "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        return result.stdout.strip()

    @staticmethod
    def set_monitor(ifname: str):
        print(" In development, see https://github.com/gusprojects008/wnlpy")
        try:
            subprocess.run(["sudo", "ip", "link", "set", ifname, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            subprocess.run(["sudo", "iw", "dev", ifname, "set", "type", "monitor"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            subprocess.run(["sudo", "ip", "link", "set", ifname, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            print(f"{ifname} configured for monitor mode!")
        except Exception as error:
            print(f"error configure {ifname} to monitor mode: {error}")

    @staticmethod
    def set_station(ifname: str):
        print(" In development, see https://github.com/gusprojects008/wnlpy")
        try:
            subprocess.run(["sudo", "ip", "link", "set", ifname, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            subprocess.run(["sudo", "iw", "dev", ifname, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            subprocess.run(["sudo", "ip", "link", "set", ifname, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            print(f"{ifname} configured for station/management mode!")
        except Exception as error:
            print(f"error configure {ifname} to station mode: {error}")

    @staticmethod
    def scan_station_mode(ifname: str = None, output_path: str = None):
        print(" In development, see https://github.com/gusprojects008/wnlpy\n")
    
        if not ifname:
            raise ValueError("Interface name is needed!")
    
        print(f" Scanning WiFi networks on {ifname}...\n")
        
        try:
            result = subprocess.run(
                ["sudo", "iw", "dev", ifname, "scan"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"Error during scan: {e}")
            return
        except FileNotFoundError:
            print("Error: 'iw' command not found. Please install wireless tools.")
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
    
        output_path = str(new_file_path("scan-station-result", ".txt", output_path))
    
        if result.stdout:
            with open(output_path, "w") as file:
                file.write(result.stdout)
        
            blocks = result.stdout.strip().split("\nBSS ")
            network_count = 0
            
            for block in blocks[1:]:
                network_count += 1
                _print_network_summary(block, network_count)
            
            print(f"\nTotal networks found: {network_count}")

    @staticmethod
    def sniff(link_type: str = "wifi", layer: int = 2, standard: str = "802.11", 
              ifname: str = None, store_filter: str = None, display_filter: str = None, 
              count: Optional[int] = None, timeout: Optional[float] = None, 
              display_interval: float = 0.0, store_callback: callable = None,
              display_callback: callable = None, stop_event: threading.Event = None,
              output_path: str = None
          ):
    
        mac_vendor_resolver = MacVendorResolver("./core/common/mac-vendors-export.json")
        parser = None
    
        if link_type == "wifi" and layer == 2 and standard == "802.11":
            parser = IEEE802_11.frames_parser
    
        if parser is None:
            raise ValueError("Unsupported sniff parameters")
    
        sock = create_raw_socket(ifname)
        output_file_path = new_file_path("framesniff-capture", ".json", output_path)
        captured_frames = []
        frame_counter = 0
        last_display_time = 0.0
    
        try:
            if timeout:
                sock.settimeout(timeout)
    
            print(f"Starting capture on {ifname}... (Press Ctrl+C to stop)")
            print(f"Store filter: {store_filter}")
            print(f"Display filter: {display_filter}")
            start_time = time.time()
    
            while True:
                if stop_event and stop_event.is_set():
                    print("Stop event received, finishing capture...")
                    break
                try:
                    frame, _ = sock.recvfrom(65535)
                    parsed_frame = parser(frame, mac_vendor_resolver)
                    if parsed_frame is None:
                        continue
                    
                    parsed_frame["counter"] = frame_counter
                    parsed_frame["raw"] = frame.hex()
                    
                    store_result, display_result = apply_filters(store_filter, display_filter, parsed_frame)
                    
                    # DEBUG: Verificar o que está sendo retornado
                    if frame_counter % 10 == 0:  # A cada 10 frames
                        print(f"Frame {frame_counter}: store_result={store_result}, display_result={display_result is not None}")
                    
                    if store_result:
                        frame_counter += 1
                        captured_frames.append(parsed_frame)
                        if store_callback:
                            store_callback(parsed_frame)
                    
                    if display_callback and display_result:
                        display_callback(display_result)
                    
                    if display_result and not display_callback:
                        current_time = time.time()
                        if store_result and current_time - last_display_time >= display_interval:
                            try:
                                print(f"[{frame_counter}] {json.dumps(display_result, ensure_ascii=False)}")
                            except Exception:
                                print(f"[{frame_counter}] {display_result}")
                            last_display_time = current_time
                    
                    if count is not None and frame_counter >= count:
                        break
                        
                except socket.timeout:
                    print("Capture timeout reached")
                    break
                except KeyboardInterrupt:
                    print("Capture interrupted by user")
                    break
                except Exception as error:
                    print(f"Error receiving frame: {error}")
                    continue
        finally:
             finish_capture(sock, start_time, captured_frames, output_file_path)   

    @staticmethod
    def set_frequency(ifname: str, frequency_mhz: str, channel: Optional[int] = None, timeout: float = 2.0) -> bool:
        frequency_mhz = str(frequency_mhz)
        attempts = [["sudo", "iw", ifname, "set", "freq", frequency_mhz]]
        if channel is not None:
            try:
                ch_str = str(int(channel))
                attempts.insert(0, ["sudo", "iw", ifname, "set", "channel", ch_str])
            except Exception as e:
                logging.error(f"Invalid channel value: {channel} ({e})")
                return False
        last_err = None
        for cmd in attempts:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                if proc.returncode != 0:
                    last_err = f"{' '.join(cmd)} -> returncode {proc.returncode} stderr:{proc.stderr.strip()}"
                    logging.error(last_err)
                    continue
                return True
            except Exception as e:
                last_err = f"Unexpected error running {' '.join(cmd)}: {e}"
                logging.error(last_err)
        return False

    @staticmethod
    def get_channels(bands: Optional[List[str]] = None) -> dict:
        bands = bands or ['2.4', '5']
        channel_map = {}
        if '2.4' in bands:
            channel_map['2.4'] = list(range(1, 14))
        if '5' in bands:
            channel_map['5'] = [
                36, 40, 44, 48, 52, 56, 60, 64,
                100, 104, 108, 112, 116, 120, 124, 128,
                132, 136, 140, 144,
                149, 153, 157, 161, 165
            ]
        return channel_map

    @staticmethod
    def channel_hopper_sync(ifname: str, channel_hopping_interval: float = 4.0, bands: [str] = ["2.4", "5"], callback: Optional[callable] = None, stop_event=None):
        bands = bands or ['2.4', '5']
        all_channels = Operations.get_channels(bands)
        channels_to_scan = []
        
        for band in bands:
            if band in all_channels and all_channels[band]:
                for channel in all_channels[band]:
                    if channel is None:
                        continue
                    try:
                        channel_int = int(channel)
                        if band == '2.4':
                            freq = 2407 + (channel_int * 5)
                        else:
                            freq = 5000 + (channel_int * 5)
                        channels_to_scan.append((channel_int, freq, band))
                    except (TypeError, ValueError) as e:
                        logging.warning(f"Invalid channel: {e}")
                        continue
        
        if not channels_to_scan:
            logging.warning("No channels to scan")
            return
        
        idx = 0
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break

                if not isinstance(idx, int) or idx is None:
                    logging.error(f"Invalid idx value: {idx}, resetting to 0")
                    idx = 0
                    continue
                    
                if idx >= len(channels_to_scan) or idx < 0:
                    idx = 0
                    
                ch, freq, band = channels_to_scan[idx]
                
                success = Operations.set_frequency(ifname, str(freq), channel=ch)
                if success:
                    logging.info(f"Channel changed {ch} {freq}/{band}")
                else:
                    logging.error(f"Channel {ch} {freq}/{band}")

                if callback:
                    try:
                        callback(ch, band)
                    except Exception as e:
                        logging.error(f"Channel hopper callback error: {e}")
                try:
                    next_idx = (idx + 1) % len(channels_to_scan)
                    if not isinstance(next_idx, int) or next_idx is None:
                        logging.error(f"Invalid next_idx: {next_idx}, resetting to 0")
                        idx = 0
                    else:
                        idx = next_idx
                except Exception as e:
                    logging.error(f"Error calculating next index: {e}")
                    idx = 0
    
                time.sleep(channel_hopping_interval)
                
        except KeyboardInterrupt:
            logging.info("Channel hopping stopped by KeyboardInterrupt")
        except Exception as e:
            logging.error(f"Unexpected error in channel hopper: {e}")
            logging.error(f"Traceback: {traceback.format_exc()}")
            logging.error(f"Current state - idx: {idx}, type: {type(idx)}, channels length: {len(channels_to_scan)}")
        finally:
            logging.info("Hopper finished.")

    @staticmethod
    def generate_22000(bitmask_message_pair: int = 2, ssid: str = None, input_file: str = None, output_file: str = "hashcat.22000") -> str:
        IEEE802_11.generate_22000(bitmask_message_pair, ssid, input_file, output_file)

    @staticmethod
    def write_pcap_from_json(dlt: str, input_file: str, output_path: str):
        if import_module("dpkt"):
           import dpkt

        output_path = new_file_path("packets", ".pcap", output_path)

        linktypes = {
            "DLT_IEEE802_11_RADIO": dpkt.pcap.DLT_IEEE802_11_RADIO,
            "DLT_EN10MB": dpkt.pcap.DLT_EN10MB,
            "DLT_BLUETOOTH_HCI_H4": dpkt.pcap.DLT_BLUETOOTH_HCI_H4,
        }

        if dlt not in linktypes:
            raise ValueError(f"Unsupported DLT: {dlt}\n{''.join(linktypes.keys())}")
        with open(output_path, "wb") as out:
            writer = dpkt.pcap.Writer(out, linktype=linktypes[dlt])
            count = 0
            for hexstr, b in iter_packets_from_json(input_file):
                writer.writepkt(b, ts=time.time())
                count += 1
                print(f"{count} packet writed: {b[:50]}...")
            writer.close()
            print(f"Output file: {output_path}")

    @staticmethod
    def send_raw(ifname: str, input_file: str, count: int = 1, interval: float = 1.0, timeout: float = None):
        sock = create_raw_socket(ifname)
    
        if timeout is not None:
            sock.settimeout(timeout)
    
        try:
            for cleaned, raw_bytes in iter_packets_from_json(input_file):
                for i in range(count):
                    try:
                        bytes_sent = sock.send(raw_bytes)
                        print(f"Frame sent ({i+1}/{count}): {bytes_sent} bytes")
    
                        if i < count - 1:
                            time.sleep(interval)
    
                    except socket.error as error:
                        print(f"Failed to send frame: {error}")
                        break
                    except Exception as error:
                        print(f"Unexpected error: {error}")
                        break
        finally:
            sock.close()

    @staticmethod
    def monitor_scan(ifname: str = None, channel_hopping: bool = True, channel_hopping_interval: float = 4.0, bands: [str] = ["2.4", "5"], timeout: float = None):
        if import_module("textual") and check_root():
            from core.tui.monitor_scan import monitor_scan
        monitor_scan(ifname=ifname, channel_hopping=channel_hopping, channel_hopping_interval=channel_hopping_interval, bands=bands, timeout=timeout, logging=logging, Operations=Operations)
