import sys
import pathlib
import argparse

modules_path = pathlib.Path(__file__).parent / "core"
sys.path.append(str(modules_path))

from user_operations import Operations

operations = Operations()

def main():
    parser = argparse.ArgumentParser(
        description="A simple tool for exploring networks and their protocols"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-interfaces", help="List all network interfaces")

    list_interface_parser = subparsers.add_parser("list-interface", help="Show info about a specific interface")
    list_interface_parser.add_argument("ifname", help="Interface name")

    set_monitor_parser = subparsers.add_parser("set-monitor", help="Set interface to monitor mode")
    set_monitor_parser.add_argument("ifname", help="Interface name")

    set_station_parser = subparsers.add_parser("set-station", help="Set interface to station/management/managed mode")
    set_station_parser.add_argument("ifname", help="Interface name")

    scan_parser = subparsers.add_parser("scan", help="Scan networks in station mode")
    scan_parser.add_argument("ifname", help="Interface name")

    set_frequency_parser = subparsers.add_parser("set-frequency", help="Set frequency on a given phy")
    set_frequency_parser.add_argument("wiphy_name", help="Wireless phy name (e.g. phy0)")
    set_frequency_parser.add_argument("frequency_mhz", help="Frequency in MHz")

    channel_hopping_parser = subparsers.add_parser("channel-hopping", help="Enable channel hopping")
    channel_hopping_parser.add_argument("wiphy_name", help="Wireless phy name (e.g. phy0)")

    sniff_parser = subparsers.add_parser("sniff", help="Sniff Wi-Fi or Bluetooth frames")
    sniff_parser.add_argument("ifname", help="Interface name")
    sniff_parser.add_argument("--link-type", choices=["wifi", "bluetooth"], default="wifi", help="Link type to sniff")
    sniff_parser.add_argument("--layer", choices=["L2", "L3"], default="L2", help="Layer to capture")
    sniff_parser.add_argument("--standard", default="802.11", help="Standard to use (e.g., 802.11, BLE)")
    sniff_parser.add_argument("--store-filter", default="", help="Filter to store frames")
    sniff_parser.add_argument("--display-filter", default="", help="Filter to display frames")
    sniff_parser.add_argument("--output-file", default=None, help="Output JSON file")
    sniff_parser.add_argument("--count", type=int, default=None, help="Number of frames to capture")
    sniff_parser.add_argument("--timeout", type=int, default=None, help="Timeout in seconds")

    eapol_parser = subparsers.add_parser("eapol-capture", help="Capture WPA2 EAPOL frames")
    eapol_parser.add_argument("ifname", help="Interface name")
    eapol_parser.add_argument("--bssid", default=None, help="Target BSSID")
    eapol_parser.add_argument("--mac", default=None, help="Target client MAC")
    eapol_parser.add_argument("--output-file", default=None, help="Output JSON file")
    eapol_parser.add_argument("--count", type=int, default=None, help="Number of frames to capture")
    eapol_parser.add_argument("--timeout", type=int, default=None, help="Timeout in seconds")

    generate_parser = subparsers.add_parser("generate-22000", help="Generate hashcat 22000 file from two EAPOL messages")
    generate_parser.add_argument("msg1", help="EAPOL message 1 in hex")
    generate_parser.add_argument("msg2", help="EAPOL message 2 in hex")
    generate_parser.add_argument("--output-file", default="hashcat.22000", help="Output file name")

    args = parser.parse_args()

    if args.command == "list-interfaces":
        print(operations.list_network_interfaces())
    elif args.command == "list-interface":
        print(operations.list_network_interface(args.ifname))
    elif args.command == "set-monitor":
        operations.set_monitor(args.ifname)
    elif args.command == "set-station":
        operations.set_station(args.ifname)
    elif args.command == "scan":
        operations.scan_station_mode(args.ifname)
    elif args.command == "set-frequency":
        operations.set_frequency(args.wiphy_name, args.frequency_mhz)
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
            output_file=args.output_file,
            count=args.count,
            timeout=args.timeout
        )
    elif args.command == "eapol-capture":
        operations.eapol_capture(
            ifname=args.ifname,
            bssid=args.bssid,
            mac=args.mac,
            output_file=args.output_file,
            count=args.count,
            timeout=args.timeout
        )
    elif args.command == "generate-22000":
        operations.generate_22000(
            eapol_msg1_hex=args.msg1,
            eapol_msg2_hex=args.msg2,
            output_file=args.output_file
        )

if __name__ == "__main__":
    main()
