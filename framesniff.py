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

if __name__ == "__main__":
    main()
