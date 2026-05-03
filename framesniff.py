#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import argcomplete
from pathlib import Path
from logging import getLogger
from core.common.constants.hashcat import *
from core.common.cli import interfaces_completer
from core.bootstrap import init

config = {
    "module_dependencies": ["rich", "dpkt", "textual"],
    "system_dependencies": ["ip", "iw"],
    "argparse": {}
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="A simple tool for exploring networks, their protocols and devices."
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose mode and save debug logs to file"
    )

    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output fullpath to save debug logs to file"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-interfaces", help="List all network interfaces")

    list_interface_parser = subparsers.add_parser("list-interface", help="Show info about a specific interface")
    list_interface_parser.add_argument("--ifname", type=str, required=True).completer = interfaces_completer

    set_monitor_parser = subparsers.add_parser("set-monitor", help="Set interface to monitor mode")
    set_monitor_parser.add_argument("--ifname", type=str, required=True).completer = interfaces_completer

    set_station_parser = subparsers.add_parser("set-station", help="Set interface to station/managed mode")
    set_station_parser.add_argument("--ifname", type=str, required=True).completer = interfaces_completer

    scan_parser = subparsers.add_parser("scan-station", help="Scan networks in station mode")
    scan_parser.add_argument("--ifname", type=str, required=True).completer = interfaces_completer
    scan_parser.add_argument("--output", "-o", type=str, help="Output filename")

    set_frequency_parser = subparsers.add_parser("set-frequency", help="Set frequency or channel on a given interface")
    set_frequency_parser.add_argument("--ifname", type=str, required=True).completer = interfaces_completer
    group = set_frequency_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--frequency", "-f", type=int, help="Frequency in MHz")
    group.add_argument("--channel", "-c", type=int, help="Channel number")
    set_frequency_parser.add_argument("--width", type=int, help="Channel width")

    sniff_parser = subparsers.add_parser("sniff", help="Sniff Wi-Fi, Bluetooth or Ethernet frames")
    sniff_parser.add_argument("--ifname", type=str, required=True).completer = interfaces_completer
    sniff_parser.add_argument(
        "--dlt", type=str,
        choices=["DLT_IEEE802_11_RADIO", "EN10MB", "DLT_BLUETOOTH_HCI_H4"],
        default="DLT_IEEE802_11_RADIO"
    )
    sniff_parser.add_argument("--simple-output", action="store_true")
    sniff_parser.add_argument("--store-filter", type=str, default=None)
    sniff_parser.add_argument("--display-filter", type=str, default=None)
    sniff_parser.add_argument("--count", type=int, default=None)
    sniff_parser.add_argument("--timeout", type=float, default=None)
    sniff_parser.add_argument("--display-interval", type=float, default=0.0)
    sniff_parser.add_argument("--output", "-o", type=str, default=None)

    generate_hashcat_parser = subparsers.add_parser("generate-hashcat", help="Generate hashcat file from json file")
    generate_hashcat_parser.add_argument("hformat", type=int, choices=[WPA_PBKDF2_PMKID_EAPOL])
    generate_hashcat_parser.add_argument(
        "--htype", type=int, choices=[HC22000_PMKID, HC22000_EAPOL],
        help=(
            f"Hash type {HC22000_PMKID} (PMKID) or {HC22000_EAPOL} (EAPOL raw frame pair)"
        )
    )
    generate_hashcat_parser.add_argument("--ssid", type=str)
    generate_hashcat_parser.add_argument("--input", "-i", type=str, required=True)
    generate_hashcat_parser.add_argument("--output", "-o", type=str)

    hextopcap_parser = subparsers.add_parser("hextopcap", help="Generate pcap from json with raw hex packets")
    hextopcap_parser.add_argument(
        "--dlt", type=str,
        choices=["DLT_IEEE802_11_RADIO", "DLT_EN10MB", "DLT_BLUETOOTH_HCI_H4"],
        default="DLT_IEEE802_11_RADIO"
    )
    hextopcap_parser.add_argument("--input", "-i", type=str)
    hextopcap_parser.add_argument("--output", "-o", type=str, default=None)

    send_raw_parser = subparsers.add_parser("send-raw", help="Send raw hex frames from an interface")
    send_raw_parser.add_argument("--ifname", type=str, required=True).completer = interfaces_completer
    send_raw_parser.add_argument("input_fullpath", type=str)
    send_raw_parser.add_argument("--count", type=int)
    send_raw_parser.add_argument("--interval", type=float)
    send_raw_parser.add_argument("--timeout", type=float)

    scan_monitor_parser = subparsers.add_parser("scan-monitor", help="Scan nearby APs and devices")
    scan_monitor_parser.add_argument("--ifname", type=str, required=True).completer = interfaces_completer
    scan_monitor_parser.add_argument(
        "--dlt", type=str,
        choices=["DLT_IEEE802_11_RADIO", "DLT_EN10MB", "DLT_BLUETOOTH_HCI_H4"],
        default="DLT_IEEE802_11_RADIO"
    )
    scan_monitor_parser.add_argument("--no-channel-hopping", dest="channel_hopping", action="store_false")
    scan_monitor_parser.add_argument("--dwell", type=float, default=4.0)
    scan_monitor_parser.add_argument("--timeout", type=float)

    gen_hop_parser = subparsers.add_parser(
        "generate-channel-hopping-config",
        help="Generate a JSON file with channel hopping settings"
    )
    gen_hop_parser.add_argument("--bands", nargs="+", type=float)
    gen_hop_parser.add_argument("--width", type=int)
    gen_hop_parser.add_argument("--dwell", type=float)
    gen_hop_parser.add_argument("--output", "-o", type=str)

    channel_hopping_parser = subparsers.add_parser("channel-hopping", help="Enable channel hopping")
    channel_hopping_parser.add_argument("--ifname", type=str, required=True).completer = interfaces_completer
    channel_hopping_parser.add_argument("--input", "-i", type=str, required=True)
    channel_hopping_parser.add_argument("--allowed", type=int, nargs="+")
    channel_hopping_parser.add_argument("--disallowed", type=int, nargs="+")
    channel_hopping_parser.add_argument("--timeout", type=float)

    argcomplete.autocomplete(parser)
    return parser

def main():
    parser = parse_args()
    config["argparse"]["parser"] = parser
    config["argparse"]["args"] = parser.parse_args()
    result = init(config)
    operations = result.operations
    logger = getLogger(__name__)
    operations.dispatch()

if __name__ == "__main__":
    main()
