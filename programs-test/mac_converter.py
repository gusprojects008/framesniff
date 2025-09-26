import struct
import psutil

interface = input("Type it interface network: ")

def get_mac(interface):
    interfaces = psutil.net_if_addrs()
    for info in interfaces.get(interface):
        if psutil.AF_LINK in info:
           return info.address

def mac_for_bytes(mac):
    return bytes(int(byte, 16) for byte in mac.split(':'))

def bytes_for_mac(mac_bytes):
    return ':'.join(format(byte, 'x') for byte in mac_bytes)


mac = get_mac(interface)
mac_bytes = mac_for_bytes(mac)

print()
print(f"{mac} => {mac.split(':')} => {mac_bytes}")
print()
print(f"{mac_bytes} => {':'.join(str(mac_bytes))} => {bytes_for_mac(mac_bytes)}")
