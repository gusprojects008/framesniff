import subprocess
import re
from typing import Optional, Tuple, List

from core.wifi.l2.ieee802_11.ieee802_11 import IEEE802_11

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
    def sniff(link_type: Optional[str] = None,
              layer: str = "L2",
              standard: str = "",
              ifname: Optional[str] = None,
              store_filter: str = "",
              display_filter: str = "",
              output_file: Optional[str] = None,
              count: Optional[int] = None,
              timeout: Optional[int] = None):
        if link_type == "wifi" and layer == "L2" and standard == "802.11":
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
    def generate_22000(eapol_msg1_hex: str, eapol_msg2_hex: str, output_file: str = "hashcat.22000") -> str:
        return IEEE802_11.WPA2Personal.generate_22000(eapol_msg1_hex, eapol_msg2_hex, output_file)
