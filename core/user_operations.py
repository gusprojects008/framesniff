import subprocess
import re
from typing import Optional, Tuple, List
import sys
import time
import json
from core.wifi.l2.ieee802_11.ieee802_11 import IEEE802_11
from core.common.useful_functions import (import_dpkt, new_file_path, iter_packets_from_json)
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

    @staticmethod
    def write_pcap_from_json(dlt: str, input_file: str, output_path: str):
        if not import_dpkt():
            sys.exit(1)
        import dpkt

        output_path = new_file_path("packets", ".pcap", output_path)        

        linktypes = {
            "DLT_IEEE802_11_RADIO": dpkt.pcap.DLT_IEEE802_11_RADIO,
            "DLT_EN10MB": dpkt.pcap.DLT_EN10MB,
            "DLT_IEEE802_11": dpkt.pcap.DLT_IEEE802_11,
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
