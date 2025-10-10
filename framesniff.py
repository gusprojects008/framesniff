import sys
import pathlib
import argparse

from core.user_operations import Operations

operations = Operations()

def main():
    parser = argparse.ArgumentParser(
        description="A simple tool for exploring networks and their protocols: Data Link Types (DLTs) Supported: "
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-interfaces", help="List all network interfaces")

    list_interface_parser = subparsers.add_parser("list-interface", help="Show info about a specific interface")
    list_interface_parser.add_argument("--ifname", "-i", required=True, help="Network interface name.")

    set_monitor_parser = subparsers.add_parser("set-monitor", help="Set interface to monitor mode")
    set_monitor_parser.add_argument("--ifname", "-i", required=True, help="Network interface name.")

    set_station_parser = subparsers.add_parser("set-station", help="Set interface to station/management/managed mode")
    set_station_parser.add_argument("--ifname", "-i", required=True, help="Network interface name.")

    scan_parser = subparsers.add_parser("station-scan", help="Scan networks in station mode")
    scan_parser.add_argument("--ifname", "-i", required=True, help="Network Interface Name")
    scan_parser.add_argument("--output", "-o", default=None, help="Output file path")

    set_frequency_parser = subparsers.add_parser("set-frequency", help="Set frequency on a given phy")
    set_frequency_parser.add_argument("--wiphy", required=True, help="Wireless phy name (e.g. phy0)")
    set_frequency_parser.add_argument("frequency_mhz", help="Frequency in MHz")

    channel_hopping_parser = subparsers.add_parser("channel-hopping", help="Enable channel hopping")
    channel_hopping_parser.add_argument("wiphy_name", help="Wireless phy name (e.g. phy0)")

    sniff_parser = subparsers.add_parser("sniff", help="Sniff Wi-Fi or Bluetooth frames")
    sniff_parser.add_argument("--link-type", choices=["wifi", "bluetooth"], default="wifi", help="Link type to sniff")
    sniff_parser.add_argument("--layer", type=int, choices=[2, 3], default=2, help="Layer to capture")
    sniff_parser.add_argument("--standard", type=str, default="802.11", help="Standard to use (e.g., 802.11, BLE)")
    sniff_parser.add_argument("--ifname", "-i", required=True, help="Interface name")
    sniff_parser.add_argument("--store-filter", default=None, help="Filter to store frames")
    sniff_parser.add_argument("--display-filter", default=None, help="Filter to display frames")
    sniff_parser.add_argument("--count", type=int, default=None, help="Number of frames to capture")
    sniff_parser.add_argument("--timeout", type=float, default=None, help="Timeout in seconds")
    sniff_parser.add_argument("--display-interval", type=float, default=1.0, help="Interval for displaying frames")
    sniff_parser.add_argument("--output", "-o", default=None, help="Output JSON file")

    eapol_parser = subparsers.add_parser("eapol-capture", help="Capture WPA2 EAPOL frames")
    eapol_parser.add_argument("--ifname", "-i", required=True, help="Network Interface Name")
    eapol_parser.add_argument("--bssid", default=None, help="Target BSSID")
    eapol_parser.add_argument("--mac", default=None, help="Target client MAC")
    eapol_parser.add_argument("--count", type=int, default=None, help="Number of frames to capture")
    eapol_parser.add_argument("--timeout", type=float, default=None, help="Timeout in seconds")
    eapol_parser.add_argument("--output", default=None, help="Output JSON file")

    generate_22000_parser = subparsers.add_parser("generate-22000", help="Generate hashcat 22000 file from json file")
    generate_22000_parser.add_argument("--bitmask", required=True, type=int, default=2, help="Bitmask message pair (1 or 2)")
    generate_22000_parser.add_argument("--ssid", required=True, help="SSID of the target network")
    generate_22000_parser.add_argument("--input", "-i", required=True, help="JSON file path")
    generate_22000_parser.add_argument("--output", "-o", default="hashcat.22000", help="Output file name")

    hextopcap_parser = subparsers.add_parser("hextopcap", help="Generates a pcap file from a json file with the raw contents of the packet.")
    hextopcap_parser.add_argument("--dlt", required=True, choices=["DLT_IEEE802_11_RADIO", "DLT_EN10MB", "DLT_BLUETOOTH_HCI_H4"], help="Data Link Type (DLT)")
    hextopcap_parser.add_argument("--input", "-i", required=True, help="Json file with raw hexadecimal packets.")
    hextopcap_parser.add_argument("--output", "-o", default=None, help="Output pcap file path.")

    send_raw_parser = subparsers.add_parser("send-raw", help="Sends a raw frame/packet in hexadecimal format from an interface.")
    send_raw_parser.add_argument("--ifname", required=True, help="Network interface name.")
    send_raw_parser.add_argument("--input", "-i", required=True, help="Json file with hexadecimal raw packets: ex: {'raw': ['01234abcdef', '01234abcdef']}.")
    send_raw_parser.add_argument("--count", type=int, default=1, help="Number of frames to send (default: 1).")
    send_raw_parser.add_argument("--interval", type=float, default=1.0, help="Interval between sends in seconds (default: 1.0).")
    send_raw_parser.add_argument("--timeout", type=float, default=None, help="Socket timeout in seconds (optional).")

    monitor_scan_parser = subparsers.add_parser("monitor-scan", help="scans nearby APs and devices (DLT_IEEE802_11_RADIO only)")
    monitor_scan_parser.add_argument("--ifname", "-i", required=True, help="Network interface name.")
    monitor_scan_parser.add_argument("--channel-hopping", default=True, help="Channel hopping, default True.")
    monitor_scan_parser.add_argument("--hopping-interval", default=4.0, help="Channel hopping interval, default 2.0 seconds.")
    monitor_scan_parser.add_argument("--bands", default=["2.4", "5"], help="Channel hopping bands, default 2.4.")
    monitor_scan_parser.add_argument("--timeout", default=None, help="Scan timeout, default None.")

    args = parser.parse_args()

    if args.command == "list-interfaces":
        print(operations.list_network_interfaces())
    elif args.command == "list-interface":
        print(operations.list_network_interface(args.ifname))
    elif args.command == "set-monitor":
        operations.set_monitor(args.ifname)
    elif args.command == "set-station":
        operations.set_station(args.ifname)
    elif args.command == "station-scan":
        operations.scan_station_mode(args.ifname, args.output)
    elif args.command == "set-frequency":
        operations.set_frequency(args.wiphy, args.frequency_mhz)
    elif args.command == "channel-hopping":
        operations.channel_hopping(args.wiphy_name)
    elif args.command == "sniff":
        operations.sniff(
            link_type=args.link_type,
            layer=args.layer,
            standard=args.standard,
            ifname=args.ifname,
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
    elif args.command == "monitor-scan":
         operations.monitor_scan(args.ifname, args.channel_hopping, args.hopping_interval, args.bands, args.timeout)

if __name__ == "__main__":
    main()
