import psutil

def getInterfaces():
    result = {}
    addresses_interfaces = psutil.net_if_addrs()
    for interface, addresses in addresses_interfaces.items():
        for address in addresses:
            if address.family == psutil.AF_LINK:
               result[interface] = address.address
    return result
   
print(getInterfaces())
               

interfaces_macs = getInterfaces()

for interface, mac in interfaces_macs.items():
    print(f"{interface} ==> {mac}\n")

