import sys
import pathlib
import argparse

from core.user_operations import Operations

operations = Operations()

def main():
    parser = argparse.ArgumentParser(
        description="A simple tool for exploring networks, their protocols and devices."
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

    set_frequency_parser = subparsers.add_parser("set-frequency", help="Set frequency on a given phy or ifname")
    set_frequency_parser.add_argument("ifname", type=str, default=None, help="Network Interface Name")
    set_frequency_parser.add_argument("frequency_mhz", type=str, default="2437", help="Frequency in MHz")
    set_frequency_parser.add_argument("--width", type=int, default=20, help="Channel width")

    sniff_parser = subparsers.add_parser("sniff", help="Sniff Wi-Fi, Bluetooth or Ethernet frames")
    sniff_parser.add_argument("ifname", type=str, default=None, help="Network interface name")
    sniff_parser.add_argument("--dlt", type=str, choices=["DLT_IEEE802_11_RADIO", "EN10MB", "DLT_BLUETOOTH_HCI_H4"], default="DLT_IEEE802_11_RADIO", help="Defines the communication standard and frame format that we will capture.")
    sniff_parser.add_argument("--store-filter", type=str, default=None, help="Filter to storage frames.")
    sniff_parser.add_argument("--display-filter", type=str, default=None, help="Filter to display frames (must comply with the storage filter).")
    sniff_parser.add_argument("--count", type=int, default=None, help="Number of frames to capture")
    sniff_parser.add_argument("--timeout", type=float, default=None, help="Timeout in seconds")
    sniff_parser.add_argument("--display-interval", type=float, default=0.0, help="Interval for displaying frames")
    sniff_parser.add_argument("--output", "-o", type=str, default=None, help="Output JSON file")

    generate_22000_parser = subparsers.add_parser("generate-22000", help="Generate hashcat 22000 file from json file")
    generate_22000_parser.add_argument("--bitmask", type=int, choices=[1, 2], default=2, required=True, help="Bitmask message pair (1 or 2)\nbitmask 1 format: {'ap_mac': '', 'sta_mac': '', 'pmkid': ''}\nbitmask 2 format: {'raw': ['eapol message 1', 'eapol message 2']}. e.g. {'raw': ['000038002f...', '000038002f...']}")
    generate_22000_parser.add_argument("--ssid", type=str, required=True, help="SSID of the target network (e.g. MyNetwork)")
    generate_22000_parser.add_argument("--input", "-i", type=str, required=True, help="JSON file path")
    generate_22000_parser.add_argument("--output", "-o", type=str, default="hashcat.22000", help="Output file name")

    hextopcap_parser = subparsers.add_parser("hextopcap", help="Generates a pcap file from a json file with the raw contents of the packet.")
    hextopcap_parser.add_argument("--dlt", type=str, choices=["DLT_IEEE802_11_RADIO", "EN10MB", "DLT_BLUETOOTH_HCI_H4"], default="DLT_IEEE802_11_RADIO", help="Defines the communication standard and frame format captured.")
    hextopcap_parser.add_argument("--input", "-i", type=str, required=True, help="Json file with raw hexadecimal packets.")
    hextopcap_parser.add_argument("--output", "-o", type=str, default=None, help="Output pcap file path.")

    send_raw_parser = subparsers.add_parser("send-raw", help="Sends a raw frame/packet in hexadecimal format from an interface.")
    send_raw_parser.add_argument("ifname", type=str, default=None, help="Network interface name")
    send_raw_parser.add_argument("--input", "-i", type=str, required=True, help="Json file with hexadecimal raw packets: ex: {'raw': ['01234abcdef', '01234abcdef']}.")
    send_raw_parser.add_argument("--count", type=int, default=1, help="Number of frames to send (default: 1).")
    send_raw_parser.add_argument("--interval", type=float, default=1.0, help="Interval between sends in seconds (default: 1.0).")
    send_raw_parser.add_argument("--timeout", type=float, default=None, help="Socket timeout in seconds (optional).")

    scan_monitor_parser = subparsers.add_parser("scan-monitor", help="scans nearby APs and devices.")
    scan_monitor_parser.add_argument("ifname", type=str, default=None, help="Network interface name")
    scan_monitor_parser.add_argument("--dlt", type=str, choices=["DLT_IEEE802_11_RADIO", "EN10MB", "DLT_BLUETOOTH_HCI_H4"], default="DLT_IEEE802_11_RADIO", help="Defines the communication standard and frame format captured.")
    scan_monitor_parser.add_argument("--no-channel-hopping", dest="channel_hopping", action="store_false", help="Disable channel hopping (enabled by default).")
    scan_monitor_parser.add_argument("--dwell", type=float, default=4.0, help="Channel hopping interval (dwell time in channel), default 4 seconds.")
    scan_monitor_parser.add_argument("--timeout", type=float, default=None, help="Time to capture frames (seconds), default None.")

    generate_channel_hopping_config = subparsers.add_parser("generate-channel-hopping-config", help="Generates a JSON file with all channels and their default settings based on the bands and dwell times.")
    generate_channel_hopping_config.add_argument("bands", nargs="+", type=float, default=[2.4], help="bands to tour, e.g: 2.4 5 6")
    generate_channel_hopping_config.add_argument("--output", "-o", type=str, default="channel-hopping-config", help="Output filename for channel hopping config.")
    generate_channel_hopping_config.add_argument("--width", type=int, default=20, help="Channel width.")
    generate_channel_hopping_config.add_argument("--dwell", type=float, default=4, help="Dwell time (seconds) float.")

    channel_hopping_parser = subparsers.add_parser("channel-hopping", help="Enable channel hopping")
    channel_hopping_parser.add_argument("ifname", type=str, default=None, help="Network Interface Name")
    channel_hopping_parser.add_argument("channel_hopping_config_filename", type=str, help="Channel hopping configuration in json file, generated by (generate-channel-hopping-config).")
    channel_hopping_parser.add_argument("--allowed", type=int, default=None, help="Channels defined in the json file that will be used.")
    channel_hopping_parser.add_argument("--disallowed", type=int, default=None, help="Channels defined in the json file that will not be used.")
    channel_hopping_parser.add_argument("--timeout", type=float, default=None, help="Channels hopping timeout (seconds).")

    args = parser.parse_args()

    if args.command == "list-interfaces":
       print(operations.list_network_interfaces())
    elif args.command == "list-interface":
       print(operations.list_network_interface(args.ifname))
    elif args.command == "set-monitor":
       operations.set_monitor(args.ifname)
    elif args.command == "set-station":
       operations.set_station(args.ifname)
    elif args.command == "scan-station":
       operations.scan_station_mode(args.ifname, args.output)
    elif args.command == "set-frequency":
       operations.set_frequency(args.ifname, args.frequency_mhz, args.width)
    elif args.command == "generate-channel-hopping-config":
        operations.generate_channel_hopping_config(bands=args.bands, channel_width=args.width, dwell=args.dwell, output_filename=args.output)
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
           output_filename=args.output
       )
    elif args.command == "generate-22000":
       operations.generate_22000(
          bitmask_message_pair=args.bitmask,
          ssid=args.ssid,
          input_filename=args.input,
          output_filename=args.output
       )
    elif args.command == "hextopcap":
       operations.write_pcap_from_json(args.dlt, args.input, args.output)
    elif args.command == "send-raw":
       operations.send_raw(args.ifname, args.input, args.count, args.interval, args.timeout)
    elif args.command == "scan-monitor":
       operations.scan_monitor(ifname=args.ifname, dlt=args.dlt, channel_hopping=args.channel_hopping, channel_hopping_interval=args.dwell, timeout=args.timeout)

if __name__ == "__main__":
    main()
