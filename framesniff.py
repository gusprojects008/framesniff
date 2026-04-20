from pathlib import Path
from logging import getLogger
import argparse

from core.common.function_utils import (check_dependencies, new_file_path, setup_logging)

module_dependencies = ["rich", "dpkt", "textual"]
executable_dependencies = ["ip", "iw"]
check_dependencies(module_dependencies=module_dependencies, executable_dependencies=executable_dependencies)

from core.common.constants.hashcat import *
from core.user_operations import Operations

operations = Operations()

def main():

    parser = argparse.ArgumentParser(
        description="A simple tool for exploring networks, their protocols and devices."
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose mode and save debug logs to file"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-interfaces", help="List all network interfaces")

    list_interface_parser = subparsers.add_parser("list-interface", help="Show info about a specific interface")
    list_interface_parser.add_argument("ifname", type=str, default=None, help="Network interface name.")

    set_monitor_parser = subparsers.add_parser("set-monitor", help="Set interface to monitor mode")
    set_monitor_parser.add_argument("ifname", type=str, default=None, help="Network interface name.")

    set_station_parser = subparsers.add_parser("set-station", help="Set interface to station/management/managed mode")
    set_station_parser.add_argument("ifname", type=str, default=None, help="Network interface name.")

    scan_parser = subparsers.add_parser("scan-station", help="Scan networks in station mode")
    scan_parser.add_argument("ifname", type=str, default=None, help="Network Interface Name")
    scan_parser.add_argument("--output", "-o", type=str, default=None, help="Output filename")

    set_frequency_parser = subparsers.add_parser(
        "set-frequency",
        help="Set frequency or channel on a given interface"
    )
    set_frequency_parser.add_argument(
        "ifname",
        type=str,
        help="Network Interface Name"
    )
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
    sniff_parser.add_argument("ifname", type=str, help="Network interface name")
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
    hextopcap_parser.add_argument("--dlt", type=str, choices=["DLT_IEEE802_11_RADIO", "EN10MB", "DLT_BLUETOOTH_HCI_H4"], default="DLT_IEEE802_11_RADIO", help="Defines the communication standard and frame format captured.")
    hextopcap_parser.add_argument("input_fullpath", type=str, help="Json file with raw hexadecimal packets.")
    hextopcap_parser.add_argument("--output", "-o", type=str, default=None, help="Output pcap file path.")

    send_raw_parser = subparsers.add_parser("send-raw", help="Sends a raw frame/packet in hexadecimal format from an interface.")
    send_raw_parser.add_argument("ifname", type=str, help="Network interface name")
    send_raw_parser.add_argument("input_fullpath", type=str, help="Json file with hexadecimal raw packets: ex: {'raw': ['01234abcdef', '01234abcdef']}.")
    send_raw_parser.add_argument("--count", type=int, help="Number of frames to send (default: 1).")
    send_raw_parser.add_argument("--interval", type=float, help="Interval between sends in seconds (default: 1.0).")
    send_raw_parser.add_argument("--timeout", type=float, help="Socket timeout in seconds (optional).")

    scan_monitor_parser = subparsers.add_parser("scan-monitor", help="scans nearby APs and devices.")
    scan_monitor_parser.add_argument("ifname", type=str, help="Network interface name")
    scan_monitor_parser.add_argument("--dlt", type=str, choices=["DLT_IEEE802_11_RADIO", "DLT_EN10MB", "DLT_BLUETOOTH_HCI_H4"], default="DLT_IEEE802_11_RADIO", help="Defines the communication standard and frame format captured.")
    scan_monitor_parser.add_argument("--no-channel-hopping", dest="channel_hopping", action="store_false", help="Disable channel hopping (enabled by default).")
    scan_monitor_parser.add_argument("--dwell", type=float, default=4.0, help="Channel hopping interval (dwell time in channel), default 4 seconds.")
    scan_monitor_parser.add_argument("--timeout", type=float, help="Time to capture frames (seconds), default None.")

    generate_channel_hopping_config = subparsers.add_parser("generate-channel-hopping-config", help="Generates a JSON file with all channels and their default settings based on the bands and dwell times.")
    generate_channel_hopping_config.add_argument("bands", nargs="+", type=float, help="bands to tour, e.g: 2.4 5 6")
    generate_channel_hopping_config.add_argument("--width", type=int, help="Channel width.")
    generate_channel_hopping_config.add_argument("--dwell", type=float, help="Dwell time (seconds) float.")
    generate_channel_hopping_config.add_argument("--output", "-o", type=str, help="Output filename for channel hopping config.")

    channel_hopping_parser = subparsers.add_parser("channel-hopping", help="Enable channel hopping")
    channel_hopping_parser.add_argument("ifname", type=str, help="Network Interface Name")
    channel_hopping_parser.add_argument("channel_hopping_config_filename", type=str, help="Channel hopping configuration in json file, generated by (generate-channel-hopping-config).")
    channel_hopping_parser.add_argument("--allowed", type=int, nargs="+", help="Channels defined in the json file that will be used.")
    channel_hopping_parser.add_argument("--disallowed", type=int, nargs="+", help="Channels defined in the json file that will not be used.")
    channel_hopping_parser.add_argument("--timeout", type=float, help="Channels hopping timeout (seconds).")

    args = parser.parse_args()

    log_file_path = str(setup_logging(args.verbose))
    logger = getLogger(__name__)

    if not log_file_path:
        logger.info(f"log file created at: {log_file_path} {type(log_file_path)}")

    if args.command == "list-interfaces":
       logger.info(operations.list_network_interfaces())
    elif args.command == "list-interface":
       logger.info(operations.list_network_interface(args.ifname))
    elif args.command == "set-monitor":
       operations.set_monitor(args.ifname)
    elif args.command == "set-station":
       operations.set_station(args.ifname)
    elif args.command == "scan-station":
       operations.scan_station_mode(args.ifname, args.output)
    elif args.command == "set-frequency":
       operations.set_frequency(args.ifname, args.frequency, args.channel, args.width)
    elif args.command == "generate-channel-hopping-config":
        operations.generate_channel_hopping_config(bands=args.bands, channel_width=args.width, dwell=args.dwell, output_fullpath=args.output)
    elif args.command == "channel-hopping":
       operations.channel_hopper(args.ifname, args.channel_hopping_config_filename, args.allowed, args.disallowed, timeout=args.timeout)
    elif args.command == "sniff":
       operations.sniff(
           ifname=args.ifname,
           dlt=args.dlt,
           store_filter=args.store_filter,
           display_filter=args.display_filter,
           count=args.count,
           timeout=args.timeout,
           display_interval=args.display_interval,
           simple_output=args.simple_output,
           output_fullpath=args.output
       )
    elif args.command == "generate-hashcat":
        line = operations.generate_hashcat(
            hformat=args.hformat,
            htype=args.htype,
            ssid=args.ssid,
            input_fullpath=args.input
        )
        with open(new_file_path(args.output, f"hashcat_{args.hformat}_{args.htype}"), "w") as f:
            f.write(line)
    elif args.command == "hextopcap":
        operations.write_pcap_from_json(args.dlt, args.input_fullpath, args.output)
    elif args.command == "send-raw":
        operations.send_raw(args.ifname, args.input_fullpath, args.count, args.interval, args.timeout)
    elif args.command == "scan-monitor":
        logger.debug(args)
        operations.scan_monitor(ifname=args.ifname, dlt=args.dlt, channel_hopping=args.channel_hopping, channel_hopping_interval=args.dwell, timeout=args.timeout)

if __name__ == "__main__":
    main()
