# https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h
# https://github.com/torvalds/linux/blob/master/include/net/netlink.h
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/genetlink.h
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/nl80211.h

# https://www.kernel.org/doc/html/next/userspace-api/netlink/intro.html
# nlmsghdr (nlmsg_len => 32bits, nlmsg_type => 16bits, nlmsg_flag => 16bbits, nlmsg_seq => 32bitsb, pid => 32bits)
# genlmsghdr (cmd => 8bits, version => 8bits, reserved => 16b)
# nlattr (nla_len => 16bits, nla_type => 16bits) + payload). *payload and length should be rounded to multiples of 4.

# Netlink messages must follow a standard memory alignment, which is 4 bytes. This way, the kernel parsers can interpret all fields, data and message headers correctly.

# The netlink message structure may change depending on the socket type and netlink message.

# Netlink constants, to facilitate the program access to values in memory.

# The netlink protocol can send multiple netlink response messages, so it's important to create functions that process them dynamically.

"""
  Program sends request with netlink to nl80211
        ↓↓↓
  Kernel receives Netlink message and directs it to nl80211
        ↓↓↓
  nl80211 interprets the requisition and communicates with the cfg8021  1 module
        ↓↓↓
  cfg80211 translate the request and communicates with the mac80211 dr  iver
        ↓↓↓
  mac80211 driver communicates with the wireless network card (hardwar  e) 
        ↓↓↓
  Wireless card processes the request and returns the response to the   mac80211 driver
        ↓↓↓
  mac80211 returns the response to cfg80211
        ↓↓↓
  cfg80211 processes the message and formats it for nl80211
        ↓↓↓
  nl80211 prepares the result (raw bytes) and send it via Netlink to t  he program
        ↓↓↓
  Program receives the netlink message and passer it
        ↓↓↓
  Program extract and processes the payload (from netlink message) and  parser it. (For exemple, the payload resulting from the scan operati  on performed by the network card)

"""
import socket
import struct
import os
import random
import time

NETLINK_GENERIC = 16
NLMSG_DONE = 0x3
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = (NLM_F_MATCH | NLM_F_ROOT)
GENL_ID_CTRL = 0x10
NL80211_GENL_NAME = b"nl80211"
genlmsghdr_version = 0x00
genlmsghdr_reserved = 0x00
CTRL_CMD_GETFAMILY = 0x03
CTRL_ATTR_FAMILY_ID = 0x01
CTRL_ATTR_FAMILY_NAME = 0x02
CTRL_ATTR_VERSION = 0x03
CTRL_ATTR_HDRSIZE = 0x04
CTRL_ATTR_MAXATTR = 0x05
CTRL_ATTR_OPS = 0x06
CTRL_ATTR_MCAST_GROUPS = 0x07
NL80211_CMD_GET_SCAN = 0x20
NL80211_CMD_TRIGGER_SCAN = 0x21
NL80211_CMD_NEW_SCAN_RESULTS = 0x22
NL80211_CMD_SET_CHANNEL = 65
NL80211_ATTR_IFINDEX = 0x03
NL80211_ATTR_SCAN_SSIDS = 0x2d
NL80211_ATTR_SCAN_FLAGS = 0x9e
NL80211_ATTR_WIPHY_FREQ = 56

def nlmsghdr_header(nlmsg_len, nlmsg_type, nlmsg_flag, seq, pid, msg):
    nlmsghdr = struct.pack("<IHHII", nlmsg_len, nlmsg_type, nlmsg_flag, seq, pid) + msg
    return nlmsghdr

def genlmsghdr_header(cmd, version, reserved):
    genlmsghdr = struct.pack("<BBH", cmd, version, reserved)
    return genlmsghdr

def netlink_attr(nla_type, nla_data):
    data_length = (len(nla_data) + 3) & ~3 # rounded to multiple of 4.
    padding = b"\x00" * (data_length - len(nla_data)) # gets the padding value needed if the data_length is not yet a multiple of 4 or if there are bytes left over.
    nlattr = struct.pack("<HH", data_length + struct.calcsize("<HH"), nla_type) + nla_data + padding
    return nlattr

def parser_nlattrs(nlattrs):
    netlink_attrs = {}
    offset = 0
    bytes_to_hex = lambda nlattr_data: int.from_bytes(nlattr_data[2], byteorder="little")

    while offset < len(nlattrs):
          nla_len, nla_type = struct.unpack_from("<HH", nlattrs[offset:])
          nla_fmt = f"<HH{nla_len - struct.calcsize('<HH')}s"
          nlattr = struct.unpack_from(nla_fmt, nlattrs, offset)
         
          offset += (nla_len + 3) & ~3
          if nla_type == CTRL_ATTR_FAMILY_ID:
             netlink_attrs["CTRL_ATTR_FAMILY_ID"] = bytes_to_hex(nlattr)
          elif nla_type == CTRL_ATTR_FAMILY_NAME:
               netlink_attrs["CTRL_ATTR_FAMILY_NAME"] = nlattr[2].strip(b"\x00")
          elif nla_type == CTRL_ATTR_VERSION:
               netlink_attrs["CTRL_ATTR_VERSION"] = bytes_to_hex(nlattr)
          elif nla_type == CTRL_ATTR_HDRSIZE:
               netlink_attrs["CTRL_ATTR_HDRSIZE"] = bytes_to_hex(nlattr)
          elif nla_type == CTRL_ATTR_MAXATTR:
               netlink_attrs["CTRL_ATTR_MAXATTR"] = bytes_to_hex(nlattr)
          elif nla_type == CTRL_ATTR_OPS:
               netlink_attrs["CTRL_ATTR_OPS"] = nlattr[2].hex()
          elif nla_type == CTRL_ATTR_MCAST_GROUPS:
               netlink_attrs["CTRL_ATTR_MCAST_GROUPS"] = nlattr[2].hex()
          else:
              netlink_attrs[f"UNKNOWN_ATTR_{nla_type}"] = nlattr

    return netlink_attrs

def send_netlink_msg(sock, nlmsg_type, nlmsg_flag, seq, pid, msg):
    nlmsg_len = struct.calcsize("<IHHII") + len(msg)
    sock.send(nlmsghdr_header(nlmsg_len, nlmsg_type, nlmsg_flag, seq, pid, msg))


def parser_kernel_response(sock):
    kernel_response = sock.recv(65536)
    offset = 0
    netlink_response = {
      "nlmsg": None,
      "genlmsghdr": None,
      "nlattrs": {
      }
    }
    nlmsg_len, nlmsg_type, nlmsg_flag, nlmsg_seq, nlmsg_pid = struct.unpack_from("<IHHII", kernel_response, offset) # use slice method for parser, if you don't have struct.unpack_from()
    offset =+ struct.calcsize("<IHHII")

    if nlmsg_type == 2:
       error_code = struct.unpack_from("<i", kernel_response, offset)[0]
       if error_code == 0:
          print("ACK received from kernel")
       else:
           print(f"kernel_returned_error: {error_code}")

    offset =+ nlmsg_len - struct.calcsize("<IHHII")

    genlmsghdr_cmd, genlmsghdr_version, genlmsghdr_reserved = struct.unpack_from("BBH", kernel_response, offset)
    offset =+ struct.calcsize("<BBH")
 
    netlink_response["nlmsg"] = (nlmsg_len, nlmsg_type, nlmsg_flag, nlmsg_seq, nlmsg_pid)
    netlink_response["genlmsghdr"] = (genlmsghdr_cmd, genlmsghdr_version, genlmsghdr_reserved)
 
    try:
       nlattrs = kernel_response[offset:]
       netlink_response["nlattrs"] = parser_nlattrs(nlattrs)
    except struct.error as error:
           netlink_response["nlattrs"] = nlattrs.hex()
 
    return netlink_response
    
def nl80211_get_family(pid, seq):
    msg = (genlmsghdr_header(CTRL_CMD_GETFAMILY, genlmsghdr_version, genlmsghdr_reserved) + netlink_attr(CTRL_ATTR_FAMILY_NAME, NL80211_GENL_NAME))

    send_netlink_msg(sock, NETLINK_GENERIC, NLM_F_REQUEST, seq, pid, msg)
    kernel_response = parser_kernel_response(sock)
    return kernel_response["nlattrs"].get("CTRL_ATTR_FAMILY_ID")
    
def nl80211_trigger_scan(sock, NL80211_FAMILY_ID, seq, pid, interface_index):
    msg = (genlmsghdr_header(NL80211_CMD_TRIGGER_SCAN, genlmsghdr_version, genlmsghdr_reserved) + netlink_attr(NL80211_ATTR_IFINDEX, interface_index) + netlink_attr(NL80211_ATTR_SCAN_SSIDS, struct.pack("<I", 0)) + netlink_attr(NL80211_ATTR_SCAN_FLAGS, struct.pack("<I", 1 << 1)))

    send_netlink_msg(sock, NL80211_FAMILY_ID, NLM_F_REQUEST | NLM_F_ACK, seq, pid, msg)
    
def nl80211_get_scan(sock, NL80211_FAMILY_ID, seq, pid, interface_index):
    msg = (genlmsghdr_header(NL80211_CMD_GET_SCAN, genlmsghdr_version, genlmsghdr_reserved) + netlink_attr(NL80211_ATTR_IFINDEX, interface_index))
    send_netlink_msg(sock, NL80211_FAMILY_ID, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, seq, pid, msg)
    kernel_response = parser_kernel_response(sock)
    return kernel_response

with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC) as sock:
     seq = 1
     pid = os.getpid()
 
     sock.bind((pid, 0))

     NL80211_FAMILY_ID = nl80211_get_family(seq, pid)
     print(NL80211_FAMILY_ID)

     interface_index = struct.pack("<I", int(input("Type it interface index: ").strip()))

     nl80211_trigger_scan(sock, NL80211_FAMILY_ID, seq, pid, interface_index)

     time.sleep(5) # time to synchronize with the kernel netlink response

     nl80211_get_scan(sock, NL80211_FAMILY_ID, seq, pid, interface_index) # tries to get the result of the kernel response using the parser_kernel_response function, but it can't get the data from the socket buffer because the kernel hasn't returned the result yet.

     print(nl80211_get_scan(sock, NL80211_FAMILY_ID, seq, pid, interface_index)) # By using print() and calling nl80211_get_scan again, the function reruns the parser_kernel_response function and thus gets the results from the kernel that are in the socket buffer. The print in this case, just gives the kernel the delay it needs to send all the messages to the socket buffer, and so the function returns them. But this may not be a good way (dynamic and intelligent) because the program is relying on manual delays and is not dealing with the possibility of the kernel sending other independent netlink messages.
