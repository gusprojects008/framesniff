import subprocess
import re
from wifi import l2
ieee80211 = l2()

class Operations:
      @staticmethod
      def list_network_interfaces():
          print(" In development, see https://github.com/gusprojects008/wnlpy")
          result = subprocess.run(["sudo", "iw", "dev"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
          return result.stdout.strip()
      
      def list_network_interface(ifname):
          print(" In development, see https://github.com/gusprojects008/wnlpy")
          result = subprocess.run(["sudo", "iw", "dev", ifname, "info"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
          return result.stdout.strip()

      def set_monitor(self, ifname):
          print(" In development, see https://github.com/gusprojects008/wnlpy")
          try:
             subprocess.run(["sudo", "ip", "link", "set", ifname, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             subprocess.run(["sudo", "iw", "dev", ifname, "set", "type", "monitor"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             subprocess.run(["sudo", "ip", "link", "set", ifname, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             print(f"{ifname} configured for monitor mode!")
          except Exception as error:
                 print(f"error configure {ifname} to monitor mode: {error}")

      def set_station(self, ifname):
          print(" In development, see https://github.com/gusprojects008/wnlpy")
          try:
             subprocess.run(["sudo", "ip", "link", "set", ifname, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             subprocess.run(["sudo", "iw", "dev", ifname, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             subprocess.run(["sudo", "ip", "link", "set", ifname, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             print(f"{ifname} configured for station/management mode!")
          except Exception as error:
                 print(f"error configure {ifname} to monitor mode: {error}")

      def scan_station_mode(self, ifname):
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
              print(blocks)

      def set_frequency(self, wiphy_name: str, frequency_mhz: str):
          print(" In development, see https://github.com/gusprojects008/wnlpy")
          subprocess.run(
              ["sudo", "iw", whphy_name, "set", "freq", str(frequency_mhz)],
              check=True
          )
          print(f"Frequency set to {frequency_mhz} MHz on phy{wiphy_index}")

      def channel_hopping(self, wiphy_index):
          print(" In development, see https://github.com/gusprojects008/wnlpy")

        def sniff(layer: str = "", standard: str = "", ifname: str = None, store_filter: str = "", display_filter: str = "", output_file: str = None):
            if layer == "L2":
                L2obj = L2()
                if standard == "802.11":
                   L2obj.IEEE802_11.sniff(ifname, store_filter, display_filter, output_file)
