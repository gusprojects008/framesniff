import subprocess
import psutil

class colors:
      red = "\033[31m"
      green = "\033[32m"
      blue = "\033[34m"
      cyan = "\033[36m"
      purple = "\033[35m"
      reset = "\033[0m"
      pink = "\033[95m"

      # FORMAT TEXT
      bright = '\033[1m'
      background_green = '\033[32m'
      background_red = '\033[41m'
      blink = '\033[5m'
      sublime = '\033[4m'

      # COLOR + BRIGHT
      sb = f'{bright}{sublime}'
      gb = f'{bright}{green}'
      bb = f'{bright}{blue}'

def show_interfaces_addrs():
    try:
       print()
       address_interfaces = psutil.net_if_addrs()
       for interfaces in address_interfaces:
           for info in address_interfaces.get(interfaces):
               if psutil.AF_LINK in info:
                  print(f"{colors.green}{info.address} => {colors.gb}{interfaces}{colors.reset}")
       print()
    except Exception as error:
           print(f"Error to get interfaces and address );\n{colors.red}{str(error)}{colors.reset}")

def set_monitor(interface_monitor_options):
    if interface_monitor_options == 1:
       print()
       interface_monitor = input("Type it interface for set monitor mode: ")
       try:
          subprocess.run(['ip', 'link', 'set', interface_monitor, 'down'])
          subprocess.run(['iw', 'dev', interface_monitor, 'set', 'type', 'monitor'])
          subprocess.run(['ip', 'link', 'set', interface_monitor, 'up'])
       except Exception as error:
              print(f"Error to the set {interface_monitor} for monitor mode ); {str(error)}")

    elif interface_monitor_options == 0:
         print()
         interface_network = input("Type it the interface wireless, for create a other interface virtual in monitor mode: ")
         print()
         try:
            subprocess.run(['iw', 'dev', interface_network, 'interface', 'add', 'wlan0monitor', 'type', 'monitor'])
            subprocess.run(['ip', 'link', 'set', 'wlan0monitor', 'up'])
         except Exception as error:
                print(f"Error to the create virtual interface in monitor mode ); {str(error)}")
    else:
        print(f"Type it {colors.red}0{colors.reset} or {colors.green}1{colors.reset}")

    print()
    interface_managed = input("Set interface for managed mode: ")
    if interface_managed:
       try:
          subprocess.run(['ip', 'link', 'set', interface_managed, 'down'])
          subprocess.run(['ip', 'addr', 'flush', 'dev', interface_managed])
          subprocess.run(['iw', 'dev', interface_managed, 'set', 'type', 'managed'])
          subprocess.run(['ip', 'link', 'set', interface_managed, 'up'])
       except Exception as error:
              print(f"Error to the set {interface_managed} for managed mode ); {colors.red}{str(error)}{colors.reset}")

    show_interfaces_addrs()

try:
   show_interfaces_addrs()
   print(f"{colors.green}Type it: {colors.gb}1{colors.reset} {colors.green}to set a interface for monitor mode. {colors.purple}Type it: {colors.gb}0{colors.reset} {colors.purple}for add interface virtual in monitor mode:{colors.reset}\n")
   interface_monitor_option = int(input(f"{colors.green}You want: Set interface for monitor mode or add virtual interface in monitor mode? {colors.gb}1{colors.reset}/{colors.gb}0{colors.reset}: "))
   set_monitor(interface_monitor_option)
except Exception as error:
       print(f"Error to the set config ): {colors.red}{str(error)}{colors.reset}")
