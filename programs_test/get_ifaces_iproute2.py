import subprocess
import re

def get_ifaces():
    ifaces_user = subprocess.run(["ip", "link", "show"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    ifaces_user_output = re.findall(r'^\d+: ([^:]+):', ifaces_user.stdout.decode().strip(), re.MULTILINE)
    return ifaces_user_output

def iface_address(iface):
    ifaces = get_ifaces()
    if iface in ifaces:
       try:
          iface_address = subprocess.run(["ip", "link", "show", iface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
          iface_address_output = re.findall('link/ether ([0-9a-fA-F:]{17})', iface_address.stdout.decode().strip())
          return iface_address_output
       except Exception as error:
              return f"Error get address interface: {iface} ); {str(error)}"
    else:
        return "Error interface not found );"

print(get_ifaces(), iface_address('wlan2'))
