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
import curses
import os
import logging
from typing import Optional, Tuple, List
from core.wifi.l2.ieee802_11.ieee802_11 import IEEE802_11
from core.common.useful_functions import (import_dpkt, new_file_path, iter_packets_from_json, MacVendorResolver)
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
              display_interval: float = 0.0, output_file: Optional[str] = None, 
              packet_callback: Optional[callable] = None):

        mac_vendor_resolver = MacVendorResolver("./core/common/mac-vendors-export.json")
        parser = None

        if link_type == "wifi" and layer == 2 and standard == "802.11":
            parser = IEEE802_11.frames_parser

        if parser is None:
            raise ValueError("Unsupported sniff parameters")

        sock = create_raw_socket(ifname)
        output_file_path = new_file_path("framesniff-capture", ".json", output_file)
        captured_frames = []
        frame_counter = 0
        last_display_time = 0.0

        try:
            if timeout:
                sock.settimeout(timeout)

            print(f"Starting capture on {ifname}... (Press Ctrl+C to stop)")
            start_time = time.time()

            while True:
                try:
                    frame, _ = sock.recvfrom(65535)
                    parsed_frame = parser(frame, mac_vendor_resolver)

                    if parsed_frame is None:
                        continue

                    parsed_frame["counter"] = frame_counter
                    parsed_frame["raw"] = frame.hex()

                    store_result, display_result = apply_filters(store_filter, display_filter, parsed_frame)

                    if store_result:
                        frame_counter += 1
                        captured_frames.append(parsed_frame)

                    if packet_callback and store_result:
                        packet_callback(parsed_frame)

                    if display_result:
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
            sock.close()
            capture_duration = time.time() - start_time
            if captured_frames:
                with open(output_file_path, "w") as file:
                    json.dump(captured_frames, file, indent=2)
                print(f"Captured {len(captured_frames)} frames in {capture_duration:.2f}s")
                print(f"Saved to: {output_file_path}")
            else:
                print("No frames captured")

    @staticmethod
    def set_frequency(ifname: str, frequency_mhz: str, channel: Optional[int] = None, timeout: float = 2.0) -> bool:
        frequency_mhz = str(frequency_mhz)
        attempts = [["sudo", "iw", ifname, "set", "freq", frequency_mhz]]
        if channel is not None:
            attempts.insert(0, ["sudo", "iw", ifname, "set", "channel", str(int(channel))])
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
    def channel_hopper_sync(ifname: str, interval: float = 2.0, bands: Optional[List[str]] = None, callback: Optional[callable] = None, stop_event=None):
        bands = bands or ['2.4', '5']
        all_channels = Operations.get_channels(bands)
        channels_to_scan = []
        for band in bands:
            if band in all_channels and all_channels[band]:
                for channel in all_channels[band]:
                    if band == '2.4':
                        freq = 2407 + (channel * 5)
                    else:
                        freq = 5000 + (channel * 5)
                    channels_to_scan.append((channel, freq, band))

        if not channels_to_scan:
            logging.warning("No channels to scan")
            return

        idx = 0
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break

                ch, freq, band = channels_to_scan[idx]
                success = Operations.set_frequency(ifname, str(freq), channel=ch)

                if success:
                    logging.info(f"Channel changed {ch} {freq}/{band}")

                if callback:
                    try:
                        callback(ch, band)
                    except Exception as e:
                        logging.error(f"Channel hopper callback error: {e}")

                idx = (idx + 1) % len(channels_to_scan)
                time.sleep(interval)
        except KeyboardInterrupt:
            logging.info("Channel hopping stopped by KeyboardInterrupt")
        except Exception as e:
            logging.error(f"Unexpected error in channel hopper: {e}")
        finally:
            logging.info("Hopper finished.")

    @staticmethod
    def monitor_scan(ifname: str = "wlan0", channel_hop: bool = True,
                     hop_interval: float = 2.0, bands: Optional[List[str]] = None,
                     timeout: Optional[float] = None):

        frame_queue = queue.Queue()
        error_queue = queue.Queue()
        networks, clients, associations = {}, {}, {}
        current_channel, current_band = 1, "2.4"
        frames_processed = 0
        start_time = time.time()
        error_message = ""
        running = True

        def process_errors():
            nonlocal error_message
            try:
                while not error_queue.empty():
                    error_msg = error_queue.get_nowait()
                    error_message = error_msg
                    logging.error(error_msg)
            except Exception:
                logging.exception("Error processing errors")

        def update_current_channel(channel, band):
            nonlocal current_channel, current_band
            current_channel = channel
            current_band = band

        def start_channel_hopper_thread():
            def hopper_thread():
                print("Channel hopper thread starting...")
                try:
                    Operations.channel_hopper_sync(
                        ifname="wlan0",
                        interval=2.0,
                        bands=['2.4', '5'],
                        callback=update_current_channel
                    )
                except Exception as e:
                    logging.error(f"Channel hopper thread error: {e}\n{traceback.format_exc()}")
        
            thread = threading.Thread(target=hopper_thread, daemon=True)
            thread.name = "channel_hopper"
            thread.start()
            print(f"Channel hopper thread started: {thread.name}")
            print(f"Active threads: {threading.active_count()}")
            for t in threading.enumerate():
                print(f"   - {t.name} (daemon: {t.daemon})")

        def detect_security(tagged_params):
            try:
                if not tagged_params:
                    return {'enc': 'UNKN', 'cipher': '', 'auth': ''}
                capabilities = tagged_params.get('capabilities_information', 0)
                rsn_info = tagged_params.get('rsn_information')
                vendor_specific = tagged_params.get('vendor_specific', {})
                if rsn_info:
                    akm_list = rsn_info.get('akm_suite_list', [])
                    cipher_list = rsn_info.get('pairwise_cipher_list', [])
                    auth = "PSK"
                    for akm in akm_list:
                        if akm.get('akm_type') in [1,3,5,12]:
                            auth = "MGT"
                        elif akm.get('akm_type') in [8,9,18]:
                            return {'enc': 'WPA3', 'cipher': 'GCMP', 'auth': 'SAE'}
                    cipher = "CCMP"
                    for c in cipher_list:
                        if c.get('cipher_type') == 2:
                            cipher = "TKIP"
                    return {'enc': 'WPA2', 'cipher': cipher, 'auth': auth}
                for oui, vendors in vendor_specific.items():
                    if oui == '00:50:f2' and vendors.get(1):
                        return {'enc': 'WPA', 'cipher': 'TKIP', 'auth': 'PSK'}
                return {'enc': 'WEP', 'cipher': 'WEP', 'auth': ''}
            except Exception:
                return {'enc': 'UNKN', 'cipher': '', 'auth': ''}

        def process_frame(parsed_frame):
            nonlocal frames_processed
            try:
                mac_hdr = parsed_frame.get('mac_hdr')
                rt_hdr = parsed_frame.get('rt_hdr', {})
                signal = rt_hdr.get('dbm_antenna_signal')
                if not mac_hdr or signal is None:
                    return

                fc = mac_hdr.get('fc', {})
                subtype_name = fc.get('subtype_name')
                bssid_info = mac_hdr.get('bssid')
                source_info = mac_hdr.get('mac_src')

                if subtype_name in ["Beacon", "Probe Response"] and bssid_info:
                    bssid = bssid_info.get('mac')
                    tagged_params = parsed_frame.get('body', {}).get('tagged_parameters', {})
                    if bssid and bssid != 'ff:ff:ff:ff:ff:ff':
                        if bssid not in networks:
                            networks[bssid] = {
                                'ssid': tagged_params.get('ssid', '[Hidden]'),
                                'channel': tagged_params.get('current_channel', current_channel),
                                'signal': -100,
                                'beacons': 0,
                                'vendor': bssid_info.get('vendor', 'Unknown'),
                                'last_seen': time.time(),
                                'security': detect_security(tagged_params)
                            }
                        net = networks[bssid]
                        net['beacons'] += 1
                        net['signal'] = max(net['signal'], signal)
                        net['last_seen'] = time.time()
                        if tagged_params.get('ssid'):
                            net['ssid'] = tagged_params['ssid']

                if source_info and bssid_info:
                    client_mac = source_info.get('mac')
                    ap_mac = bssid_info.get('mac')
                    if client_mac and ap_mac and client_mac != ap_mac and client_mac != 'ff:ff:ff:ff:ff:ff':
                        if client_mac not in clients:
                            clients[client_mac] = {
                                'vendor': source_info.get('vendor', 'Unknown'),
                                'signal': -100,
                                'frames': 0,
                                'last_seen': time.time()
                            }
                        cli = clients[client_mac]
                        cli['frames'] += 1
                        cli['signal'] = max(cli['signal'], signal)
                        cli['last_seen'] = time.time()
                        associations[client_mac] = ap_mac
                frames_processed += 1
            except Exception as e:
                error_queue.put(f"Frame processing error: {e}")
                logging.exception("Frame processing error")

        def start_sniff_thread():
            def sniff_thread():
                try:
                    def packet_callback(parsed_frame):
                        try:
                            frame_queue.put(parsed_frame)
                        except Exception:
                            error_queue.put("Packet callback error")
                            logging.exception("Packet callback error")
                    Operations.sniff(
                        ifname=ifname,
                        store_filter="mac_hdr.fc.type == 0 or mac_hdr.fc.type == 2",
                        display_filter=None,
                        display_interval=0,
                        timeout=timeout,
                        packet_callback=packet_callback
                    )
                except Exception:
                    error_msg = traceback.format_exc()
                    error_queue.put(error_msg)
                    logging.exception("Sniff thread error")
            thread = threading.Thread(target=sniff_thread, daemon=True, name="sniffer")
            thread.start()
            logging.info(f"Sniff thread started: {thread.name}")

        def process_queued_frames():
            processed_count = 0
            while not frame_queue.empty() and processed_count < 50:
                try:
                    process_frame(frame_queue.get_nowait())
                    processed_count += 1
                except queue.Empty:
                    break

        def curses_ui(stdscr):
            nonlocal running
            curses.curs_set(0)
            stdscr.timeout(100)
            if curses.has_colors():
                curses.start_color()
                curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
                curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
                curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
                curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
                curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)

            while running:
                process_queued_frames()
                process_errors()
                key = stdscr.getch()
                if key in (ord('q'), ord('Q')):
                    running = False
                    break
                stdscr.clear()
                height, width = stdscr.getmaxyx()
                duration = time.time() - start_time
                hop_status = "ON" if channel_hop else "OFF"
                header = f"Network Scanner | Chan: {current_channel}({current_band}GHz) | Frames: {frames_processed} | Networks: {len(networks)} | Clients: {len(clients)} | Time: {duration:.0f}s | Hop: {hop_status}"
                stdscr.addstr(0, 0, header[:width-1], curses.A_REVERSE)

                start_row = 2 if error_message else 1
                if error_message:
                    stdscr.addstr(1, 0, f"ERROR: {error_message}"[:width-1], curses.color_pair(1) | curses.A_BOLD)

                networks_start = start_row
                stdscr.addstr(networks_start, 0, "NETWORKS:", curses.A_BOLD)
                networks_start += 1
                header_net = "BSSID              CH PWR  BCNS ESSID              ENC     CLIENTS VENDOR"
                stdscr.addstr(networks_start, 0, header_net[:width-1], curses.A_UNDERLINE)
                networks_start += 1

                for i, (bssid, info) in enumerate(sorted(networks.items(), key=lambda x: x[1]['signal'], reverse=True)[:10]):
                    if networks_start + i >= height - 5:
                        break
                    client_count = sum(1 for client, ap in associations.items() if ap == bssid)
                    security = info['security']
                    row = f"{bssid[:17]:17} {info['channel']:2} {info['signal']:3} {info['beacons']:5} {info['ssid'][:18]:18} {security['enc']:7} {client_count:7} {info['vendor'][:15]:15}"
                    stdscr.addstr(networks_start + i, 0, row[:width-1])

                clients_start = networks_start + 11
                stdscr.addstr(clients_start, 0, "CLIENTS:", curses.A_BOLD)
                clients_start += 1
                header_cli = "MAC               PWR  FRAMES ESSID              VENDOR"
                stdscr.addstr(clients_start, 0, header_cli[:width-1], curses.A_UNDERLINE)
                clients_start += 1

                for i, (client_mac, info) in enumerate(sorted(clients.items(), key=lambda x: x[1]['signal'], reverse=True)[:5]):
                    if clients_start + i >= height - 1:
                        break
                    associated_ap = associations.get(client_mac, '')
                    ssid = networks.get(associated_ap, {}).get('ssid', '(not associated)')
                    row = f"{client_mac[:17]:17} {info['signal']:3} {info['frames']:6} {ssid[:18]:18} {info['vendor'][:15]:15}"
                    stdscr.addstr(clients_start + i, 0, row[:width-1])

                #if height > 0:
                    #stdscr.addstr(height-1, 10, "Press 'q' to quit"[:width-1], curses.A_REVERSE)
                stdscr.refresh()
                time.sleep(0.1)

        if os.geteuid() != 0:
            logging.warning("Not running as root - may not capture packets")

        start_sniff_thread()
        if channel_hop:
            start_channel_hopper_thread()
        curses.wrapper(curses_ui)
        running = False
        logging.info("Network Scanner finished")

    @staticmethod
    def generate_22000(bitmask_message_pair: int = 2, ssid: str = None, input_file: str = None, output_file: str = "hashcat.22000") -> str:
        IEEE802_11.generate_22000(bitmask_message_pair, ssid, input_file, output_file)

    @staticmethod
    def write_pcap_from_json(dlt: str, input_file: str, output_path: str):
        if not import_dpkt():
            sys.exit(1)

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
if __name__ == "__main__":
   Operations.monitor_scan("wlan0")
