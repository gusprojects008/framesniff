import socket
import struct
import os
import random
import time

def nlmsg_builder(nlcmd, nlattr, type, flags, seq):
    try:
        if isinstance(nlattr, list):
            nlattr_bytes = b''.join(nlattr)
        else:
            nlattr_bytes = nlattr

        nlmsg_len = struct.calcsize("IHHII") + len(nlcmd) + len(nlattr_bytes)
        nlmsg = struct.pack("IHHII", nlmsg_len, type, flags, seq, os.getpid()) + nlcmd + nlattr_bytes
        return nlmsg
    except struct.error as e:
        print(f"Error packing Netlink message: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise

def parser_kernel_response(nlmsg_kernel):
    nlmsghdr = struct.unpack("IHHII", nlmsg_kernel[:struct.calcsize("IHHII")])
    nlmsghdr_len = struct.calcsize("IHHII")

    genlmsghdr = struct.unpack("BBH", nlmsg_kernel[nlmsghdr_len:nlmsghdr_len + struct.calcsize("BBH")])
    genlmsghdr_len = nlmsghdr_len + struct.calcsize("BBH")

    nlmsg_response = {}
    nlmsg_response["nlmsghdr"] = nlmsghdr
    nlmsg_response["genlmsghdr"] = genlmsghdr
    nlmsg_response["nlattrs"] = {}

    nlattrs_bytes = nlmsg_kernel[genlmsghdr_len:]
    offset = 0

    while offset < len(nlattrs_bytes):
        nla_len, nla_type = struct.unpack_from("HH", nlattrs_bytes, offset)
        nlattr = nlattrs_bytes[offset:offset + nla_len]
        nla_fmt = f"HH{nla_len - struct.calcsize('HH')}s"

        if nla_type == 1:
            nlmsg_response["nlattrs"]["CTRL_ATTR_FAMILY_ID"] = struct.unpack(nla_fmt, nlattr)
        elif nla_type == 2:
            nlmsg_response["nlattrs"]["CTRL_ATTR_FAMILY_NAME"] = struct.unpack(nla_fmt, nlattr)
        elif nla_type == 3:
            nlmsg_response["nlattrs"]["CTRL_ATTR_VERSION"] = struct.unpack(nla_fmt, nlattr)
        elif nla_type == 4:
            nlmsg_response["nlattrs"]["CTRL_ATTR_HDRSIZE"] = struct.unpack(nla_fmt, nlattr)
        elif nla_type == 5:
            nlmsg_response["nlattrs"]["CTRL_ATTR_MAXATTR"] = struct.unpack(nla_fmt, nlattr)
        elif nla_type == 6:
            nlmsg_response["nlattrs"]["CTRL_ATTR_OPS"] = struct.unpack(nla_fmt, nlattr)
        else:
            pass

        offset += (nla_len + 3) & ~3

    return nlmsg_response

def nl80211_get_family():
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16) as sock:
        genlmsghdr = struct.pack("BBH", 3, 1, 0)
        genlattr = struct.pack("HH", struct.calcsize("HH") + len(b"nl80211\x00"), 2) + b"nl80211\x00"
        nlmsg_generic = nlmsg_builder(genlmsghdr, genlattr, 0x10, 1, 1)

        sock.bind((os.getpid(), 0))
        sock.send(nlmsg_generic)

        kernel_response = sock.recv(65536)
        family_id = parser_kernel_response(kernel_response)["nlattrs"]["CTRL_ATTR_FAMILY_ID"][2].strip(b"\x00").hex()
    return family_id

def nl80211_get_scan(nl80211_familyID, iface):
    genlmsghdr = struct.pack("BBH", 0x20, 0, 0)
    nlattr = struct.pack("HH", struct.calcsize("HH") + len(iface), 0x03) + iface
    nlmsg = nlmsg_builder(genlmsghdr, nlattr, nl80211_familyID, 1 | 4 | (0x100 | 0x200), 1)
    return nlmsg

def random_mac():
    mac = [random.randint(0x00, 0xFF) for _ in range(6)]
    return ':'.join(f"{hex_byte:02x}" for hex_byte in mac)

def nl80211_trigger_scan(iface):
    nl80211_family = int(nl80211_get_family(), 16)

    genlmsghdr = struct.pack("BBH", 0x21, 0, 0)
    nl80211_nlattr_iface = struct.pack("HH", struct.calcsize("HH") + len(iface), 3) + iface
    nl80211_nlattr_max_ssids = struct.pack("HHI", struct.calcsize("HHI"), 0x2d, 0)
    nl80211_nlattr_flags = struct.pack("HHI", struct.calcsize("HHI"), 0x9e, 1 << 1)
    nl80211_nlattrs = [nl80211_nlattr_iface, nl80211_nlattr_max_ssids, nl80211_nlattr_flags]

    nlmsg_scan = nlmsg_builder(genlmsghdr, nl80211_nlattrs, nl80211_family, 1, 1)
    nlmsg_get_scan = nl80211_get_scan(nl80211_family, iface)

    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16) as sock:
        sock.bind((os.getpid(), 0))
        sock.send(nlmsg_scan)
        time.sleep(10)
        sock.send(nlmsg_get_scan)
        kernel_response = parser_kernel_response(sock.recv(65536))
        print(kernel_response)

try:
    interface_index = struct.pack("I", int(input("Type it interface index: ").strip()))
except ValueError:
    print("Invalid input. Please enter a valid integer.")
    exit(1)

nl80211_trigger_scan(interface_index)
