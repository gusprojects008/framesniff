#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import argcomplete
from pathlib import Path
from logging import getLogger
from cli_core.files import new_file_path
from core.common.constants.hashcat import *
from core.common.cli import interfaces_completer
from core.bootstrap import init

config = {
    "module_dependencies": ["rich", "dpkt", "textual"],
    "system_dependencies": ["ip", "iw"],
    "args": None
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="A simple tool for exploring networks, their protocols and devices."
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose mode and save debug logs to file"
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output fullpath to save debug logs to file"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-interfaces", help="List all network interfaces")

    list_interface_parser = subparsers.add_parser("list-interface", help="Show info about a specific interface")
    list_interface_parser.add_argument("--ifname", type=str, required=True, help="Network interface name.").completer = interfaces_completer

    set_monitor_parser = subparsers.add_parser("set-monitor", help="Set interface to monitor mode")
    set_monitor_parser.add_argument("--ifname", type=str, required=True, help="Network interface name.").completer = interfaces_completer

    set_station_parser = subparsers.add_parser("set-station", help="Set interface to station/management/managed mode")
    set_station_parser.add_argument("--ifname", type=str, required=True, help="Network interface name.").completer = interfaces_completer

    scan_parser = subparsers.add_parser("scan-station", help="Scan networks in station mode")
    scan_parser.add_argument("--ifname", type=str, required=True, help="Network interface name.").completer = interfaces_completer
    scan_parser.add_argument("--output", "-o", type=str, help="Output filename")

    set_frequency_parser = subparsers.add_parser(
        "set-frequency",
        help="Set frequency or channel on a given interface"
    )
    set_frequency_parser.add_argument("--ifname", type=str, required=True, help="Network interface name.").completer = interfaces_completer
    group = set_frequency_parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--frequency", "-f",
        type=int,
        help="Frequency in MHz"
    )
    group.add_argument(
        "--channel", "-c",
        type=int,
        help="Channel"
    )
    set_frequency_parser.add_argument(
        "--width",
        type=int,
        help="Channel width"
    )

    sniff_parser = subparsers.add_parser("sniff", help="Sniff Wi-Fi, Bluetooth or Ethernet frames")
    sniff_parser.add_argument("--ifname", type=str, required=True, help="Network interface name.").completer = interfaces_completer
    sniff_parser.add_argument("--dlt", type=str, choices=["DLT_IEEE802_11_RADIO", "EN10MB", "DLT_BLUETOOTH_HCI_H4"], default="DLT_IEEE802_11_RADIO", help="Defines the communication standard and frame format that we will capture.")
    sniff_parser.add_argument("--simple-output", action="store_true", help="Simple output (JSON without indentation, more optimized, consumes less storage.)")
    sniff_parser.add_argument("--store-filter", type=str, default=None, help="Filter to storage frames.")
    sniff_parser.add_argument("--display-filter", type=str, default=None, help="Filter to display frames (must comply with the storage filter).")
    sniff_parser.add_argument("--count", type=int, default=None, help="Number of frames to capture")
    sniff_parser.add_argument("--timeout", type=float, default=None, help="Timeout in seconds")
    sniff_parser.add_argument("--display-interval", type=float, default=0.0, help="Interval for displaying frames")
    sniff_parser.add_argument("--output", "-o", type=str, default=None, help="Output JSON file")

    generate_hashcat_parser = subparsers.add_parser(
        "generate-hashcat",
        help="Generate hashcat file from json file"
    )
    
    generate_hashcat_parser.add_argument("hformat", type=int, choices=[WPA_PBKDF2_PMKID_EAPOL], help="Hashcat output format")
    
    generate_hashcat_parser.add_argument(
        "--htype",
        type=int,
        choices=[HC22000_PMKID, HC22000_EAPOL],
        help=(
            f"Hash type {HC22000_PMKID} (PMKID) format:\n"
            "  {'ap_mac': '', 'sta_mac': '', 'pmkid': ''}\n"
            f"Hash type {HC22000_EAPOL} (EAPOL) format:\n"
            "  {'raw': ['frame eapol message 1', 'frame eapol message 2']}\n"
            "  e.g. {'raw': ['000038002f...', '000038002f...']}"
        )
    )
    
    generate_hashcat_parser.add_argument(
        "--ssid",
        type=str,
        help="SSID of the target network"
    )
    
    generate_hashcat_parser.add_argument(
        "--input",
        "-i",
        type=str,
        required=True,
        help="JSON file path"
    )
    
    generate_hashcat_parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Output file name"
    )

    hextopcap_parser = subparsers.add_parser("hextopcap", help="Generates a pcap file from a json file with the raw contents of the packet.")
    hextopcap_parser.add_argument("--dlt", type=str, choices=["DLT_IEEE802_11_RADIO", "DLT_EN10MB", "DLT_BLUETOOTH_HCI_H4"], default="DLT_IEEE802_11_RADIO", help="Defines the communication standard and frame format captured.")
    hextopcap_parser.add_argument("--input", "-i", type=str, help="Json file with raw hexadecimal packets.")
    hextopcap_parser.add_argument("--output", "-o", type=str, default=None, help="Output pcap file path.")

    send_raw_parser = subparsers.add_parser("send-raw", help="Sends a raw frame/packet in hexadecimal format from an interface.")
    send_raw_parser.add_argument("--ifname", type=str, required=True, help="Network interface name.").completer = interfaces_completer
    send_raw_parser.add_argument("input_fullpath", type=str, help="Json file with hexadecimal raw packets: ex: {'raw': ['01234abcdef', '01234abcdef']}.")
    send_raw_parser.add_argument("--count", type=int, help="Number of frames to send (default: 1).")
    send_raw_parser.add_argument("--interval", type=float, help="Interval between sends in seconds (default: 1.0).")
    send_raw_parser.add_argument("--timeout", type=float, help="Socket timeout in seconds (optional).")

    scan_monitor_parser = subparsers.add_parser("scan-monitor", help="scans nearby APs and devices.")
    scan_monitor_parser.add_argument("--ifname", type=str, required=True, help="Network interface name.").completer = interfaces_completer
    scan_monitor_parser.add_argument("--dlt", type=str, choices=["DLT_IEEE802_11_RADIO", "DLT_EN10MB", "DLT_BLUETOOTH_HCI_H4"], default="DLT_IEEE802_11_RADIO", help="Defines the communication standard and frame format captured.")
    scan_monitor_parser.add_argument("--no-channel-hopping", dest="channel_hopping", action="store_false", help="Disable channel hopping (enabled by default).")
    scan_monitor_parser.add_argument("--dwell", type=float, default=4.0, help="Channel hopping interval (dwell time in channel), default 4 seconds.")
    scan_monitor_parser.add_argument("--timeout", type=float, help="Time to capture frames (seconds), default None.")

    generate_channel_hopping_config = subparsers.add_parser("generate-channel-hopping-config", help="Generates a JSON file with all channels and their default settings based on the bands and dwell times.")
    generate_channel_hopping_config.add_argument("--bands", nargs="+", type=float, help="bands to tour, e.g: 2.4 5 6")
    generate_channel_hopping_config.add_argument("--width", type=int, help="Channel width.")
    generate_channel_hopping_config.add_argument("--dwell", type=float, help="Dwell time (seconds) float.")
    generate_channel_hopping_config.add_argument("--output", "-o", type=str, help="Output filename for channel hopping config.")

    channel_hopping_parser = subparsers.add_parser("channel-hopping", help="Enable channel hopping")
    channel_hopping_parser.add_argument("--ifname", type=str, required=True, help="Network interface name.").completer = interfaces_completer
    channel_hopping_parser.add_argument("--input", "-i", type=str, required=True, help="Channel hopping configuration in json file, generated by (generate-channel-hopping-config).")
    channel_hopping_parser.add_argument("--allowed", type=int, nargs="+", help="Channels defined in the json file that will be used.")
    channel_hopping_parser.add_argument("--disallowed", type=int, nargs="+", help="Channels defined in the json file that will not be used.")
    channel_hopping_parser.add_argument("--timeout", type=float, help="Channels hopping timeout (seconds).")

    argcomplete.autocomplete(parser)

    return parser, parser.parse_args()

def main():
    parser, args = parse_args()
    config["args"] = args
    result = init(config)
    operations = result.operations
    logger = getLogger(__name__)
    operations.dispatch(args)
     
if __name__ == "__main__":
    main()
