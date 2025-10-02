import subprocess
import re
from typing import Optional, Tuple, List
import sys
import time
from core.wifi.l2.ieee802_11.ieee802_11 import IEEE802_11
from core.common.useful_functions import (import_dpkt, new_file_path)
from core.common.sockets import create_raw_socket

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
    def scan_station_mode(ifname: str):
        print(" In development, see https://github.com/gusprojects008/wnlpy")
        result = subprocess.run(
            ["sudo", "iw", "dev", ifname, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        blocks = result.stdout.strip().split("\nBSS ")
        for block in blocks[1:]:
            bssid_match = re.search(r"^([0-9a-f:]{17})", block)
            ssid_match = re.search(r"SSID: (.+)", block)
            signal_match = re.search(r"signal: ([-\d.]+)", block)
            caps = []
            if "WPA3" in block or "SAE" in block:
                caps.append("WPA3")
            if "WPA2" in block or "RSN:" in block:
                caps.append("WPA2")
            if "WPA:" in block:
                caps.append("WPA")
            if "privacy" in block and not caps:
                caps.append("WEP/OPEN")
            if "Management frame protection: required" in block:
                caps.append("PMF required")
            elif "Management frame protection: capable" in block:
                caps.append("PMF capable")
            vendor_match = re.search(r"Manufacturer: (.+)", block)
            print(block)

    @staticmethod
    def set_frequency(wiphy_name: str, frequency_mhz: str):
        print(" In development, see https://github.com/gusprojects008/wnlpy")
        subprocess.run(["sudo", "iw", wiphy_name, "set", "freq", str(frequency_mhz)], check=True)
        print(f"Frequency set to {frequency_mhz} MHz on {wiphy_name}")

    @staticmethod
    def channel_hopping(wiphy_index: int):
        print(" In development, see https://github.com/gusprojects008/wnlpy")

    @staticmethod
    def sniff(
              link_type: str = "wifi",
              layer: int = 2,
              standard: float = 802.11,
              ifname: Optional[str] = None,
              store_filter: str = "",
              display_filter: str = "",
              output_file: Optional[str] = None,
              count: Optional[int] = None,
              timeout: Optional[int] = None
        ):
        if link_type == "wifi" and layer == 2 and standard == 802.11:
            return IEEE802_11.sniff(
                ifname=ifname,
                store_filter=store_filter,
                display_filter=display_filter,
                output_file=output_file,
                count=count,
                timeout=timeout
            )
        raise ValueError("Unsupported sniff parameters")

    @staticmethod
    def eapol_capture(ifname: str = None,
            bssid: Optional[str] = None,
            mac: Optional[str] = None,
            output_file: Optional[str] = None,
            count: Optional[int] = None,
            timeout: Optional[int] = None,
            store_filter: str = "",
            display_filter: str = "") -> tuple:
        if not ifname:
            raise ValueError("Interface name is required")
        return IEEE802_11.WPA2Personal.eapol_capture(
            ifname=ifname,
            bssid=bssid,
            mac=mac,
            output_file=output_file,
            count=count,
            timeout=timeout,
            store_filter=store_filter,
            display_filter=display_filter
        )

    @staticmethod
    def generate_22000(ssid: str = None, eapol_msg1_hex: str = None, eapol_msg2_hex: str = None, output_file: str = "hashcat.22000") -> str:
        return IEEE802_11.WPA2Personal.generate_22000(ssid, eapol_msg1_hex, eapol_msg2_hex, output_file)

    # write frame or packet in pcap file
    @staticmethod
    def hex_to_pcap(dlt: str, input_file: str = None, output_path: str = None):
        if not import_dpkt():
            sys.exit(1)

        import dpkt

        output_path = new_file_path("packets", ".pcap", output_path)

        linktypes = {
            "DLT_IEEE802_11_RADIO": dpkt.pcap.DLT_IEEE802_11_RADIO,
        }

        if dlt not in linktypes:
            raise ValueError(f"Unsupported DLT: {dlt}\nSupported DLTs:\n{', '.join(linktypes.keys())}")

        def clean_hex_string(hex_str: str) -> str:
            return re.sub(r'[^0-9a-fA-F]', '', hex_str)

        packet_count = 0

        with open(input_file, "r") as infile, open(output_path, "wb") as outfile:
            writer = dpkt.pcap.Writer(outfile, linktype=linktypes[dlt])

            if input_file.endswith(".json"):
                try:
                    data = json.load(infile)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Invalid JSON input file: {e}")

                if not isinstance(data, list):
                    raise ValueError("JSON must contain a list of packet objects")

                for idx, obj in enumerate(data, 1):
                    if "raw" not in obj:
                        print(f"[-] Skipping object {idx}, no 'raw' field")
                        continue

                    clean_hex = clean_hex_string(obj["raw"])
                    if not clean_hex:
                        continue

                    if len(clean_hex) % 2 != 0:
                        print(f"[-] Warning: Odd-length hex string in JSON object {idx}, trimming last character")
                        clean_hex = clean_hex[:-1]

                    try:
                        pkt_bytes = bytes.fromhex(clean_hex)
                        writer.writepkt(pkt_bytes, ts=time.time())
                        packet_count += 1
                        print(f"[+] Packet {packet_count}: {len(pkt_bytes)} bytes (from JSON)")
                    except ValueError as error:
                        print(f"[-] Error processing JSON object {idx}: {error}")
                        raise

            else:
                current_packet_hex = []
                for line_num, line in enumerate(infile, 1):
                    line = line.strip()

                    if line == "---":
                        if current_packet_hex:
                            full_hex = "".join(current_packet_hex)
                            clean_hex = clean_hex_string(full_hex)

                            if clean_hex:
                                if len(clean_hex) % 2 != 0:
                                    print(f"[-] Warning: Odd-length hex string for packet {packet_count + 1}, trimming last character")
                                    clean_hex = clean_hex[:-1]

                                try:
                                    pkt_bytes = bytes.fromhex(clean_hex)
                                    writer.writepkt(pkt_bytes, ts=time.time())
                                    packet_count += 1
                                    print(f"[+] Packet {packet_count}: {len(pkt_bytes)} bytes (from TXT)")
                                except ValueError as error:
                                    print(f"[-] Error processing packet {packet_count + 1} at line {line_num}: {error}")
                                    raise

                            current_packet_hex = []
                    else:
                        current_packet_hex.append(line)

                if current_packet_hex:
                    full_hex = "".join(current_packet_hex)
                    clean_hex = clean_hex_string(full_hex)

                    if clean_hex:
                        if len(clean_hex) % 2 != 0:
                            print(f"[-] Warning: Odd-length hex string for final packet, trimming last character")
                            clean_hex = clean_hex[:-1]

                        try:
                            pkt_bytes = bytes.fromhex(clean_hex)
                            writer.writepkt(pkt_bytes, ts=time.time())
                            packet_count += 1
                            print(f"[+] Packet {packet_count}: {len(pkt_bytes)} bytes (from TXT)")
                        except ValueError as error:
                            print(f"[-] Error processing final packet: {error}")
                            raise

            writer.close()
            print(f"[+] Finished: {packet_count} packets written to {output_path}")

    @staticmethod
    def send_raw(ifname: str, raw_hex_frame: str = None, count: int = 1, interval: int = 1, timeout: int = None):
        sock = create_raw_socket(ifname)
    
        if raw_hex_frame is None:
            raise ValueError("The frame must be in hexadecimal!")
        
        raw_frame = bytes.fromhex(raw_hex_frame.replace(":", "").replace(" ", ""))
        
        if timeout is not None:
            sock.settimeout(timeout)
        
        for i in range(count):
            try:
                bytes_sent = sock.send(raw_frame)
                print(f"Frame sent ({i+1}/{count}): {bytes_sent} bytes")
                
                if i < count - 1:
                    time.sleep(interval)
                    
            except socket.error as error:
                print(f"Failed to send frame: {error}")
                break
            except Exception as error:
                print(f"Unexpected error: {error}")
                break
