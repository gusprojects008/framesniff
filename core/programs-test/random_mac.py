import re
import random

def random_mac():
    mac = [random.randint(0x00, 0xFF) for _ in range(6)]
    return ':'.join(f"{hex_byte:02x}" for hex_byte in mac)

def mac_byte(mac):
    return bytes(int(hex_byte, 16) for hex_byte in mac.split(':'))

print(random_mac(), mac_byte(random_mac()))
