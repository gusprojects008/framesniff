### EXPLORE THE PROTOCOL NETLINK AND SOCKETS:
### THE NETLINK PROTOCOL IS A LINUX PROTOCOL CREATED AND USED TO INTERACT WITH THE LINUX KERNEL THROUGH
### NETLINK SOCKETS, THERE ARE DIFFERENT TYPES OF NETLINK SOCKETS AND EACH ONE IS USED FOR DIFFERENT OPERATIONS IN THE SYSTEM. IN NETLINK SOCKETS, MESSAGES ARE USED THAT FOLLOW A STANDARD STRUCTURE AND DIFFER 
### ACCORDING TO THE TYPE OF NETLINK SOCKET.

### COMMUNICATION OCCURS THROUGH NETLINK SOCKETS, WHERE MESSAGES ARE SENT TO THE KERNEL USING SPECIFIC FUNCTIONS, 
### AND THE KERNEL RETURNS RESPONSES THROUGH THE SOCKET CREATED BETWEEN THE PROGRAM(user process enviroment)
### AND THE KERNEL.
### WORKING NETLINK COMMUNICATION, PACKET(nlmsg(NetLinkMessage)):
### NLMSGHDR == NL(netlink) MSG(message) HDR(header) # nlmsghdr: LENGTH(4 BYTES), TYPE(2 BYTES), FLAGS(2 BYTES), SEQ(4 BYTES), PID(4 BYTES)
### THE NLMSGHDR IS STANDARD IN A NETLINK MESSAGE, BUT AFTER HEADER THE OTHERS INFORMATIONS MAY CHANGE 
### ACCORDING TO THE TYPE OF NETLINK SOCKET.

### THE NETLINK ROUTE SOCKET IS USED TO COMMUNICATE WITH THE KERNEL AND PERFORM OPERATIONS ON NETWORK ADAPTER
### SYSTEMS, SUCH AS OBTAINING INFORMATION FROM THEM AND CONFIGURING THEM.
### THE GENERIC NETLINK SOCKET IS USED TO COMMUNICATE WITH THE KERNEL AND CREATE A NEW PROTOCOL TO COMMUNICATE
### WITH THE KERNEL IN SPECIFIC WAYS AND PERFORM DIFFERENT OPERATIONS.

### THERE ARE OTHER TYPES OF NETLINK SOCKETS AND ARE USED FOR VARIOUS OPERATIONS DIFFERENTS.
### AND EACH NETLINK SOCKET OWN FUNCTIONS AND DIFFERENT MESSAGES AFTER THE DEFAULT HEADER NETLINK(nlmsghdr),
### TO DO DIFFERENTS OPERATIONS.

### THE NETLINK ROUTE, AFTER DEFAULT HEADER NLMSG, EACH MESSAGE OWN A FUNCTION AND DIFFERENT STRUCTURE OF 
### MESSAGE, THE MESSAGE AFTER THE HEADER(NETLINK) ARE MESSAGES: ifinfomsg OR rtmsg AND EACH OF THESE MESSAGES
### HAS A SPECIFIC STRUCTURE.

### THE GENERIC NETLINK FOLLOW A STRUCTURE OF MESSAGE AND HEADER EPECIFIC AFTER THE HEADER NETLINK.
### THE HEADER NETLINK GENERIC: genlmsghdr(cmd(GENERIC COMMAND TO SEND), version(SUBSYSTEM VERSION THAT THE MESSAGE IS COMMUNICATING), reserved(FIELD RESERVED TO FUTURE USE)) 
### AFTER HEADER NETLINK GENERIC(genlmsghdr) COMES nlattr, INFORMATION NECESSARY FOR OPERATION AMONG OTHER 
### ATTRIBUTES, nlattr IS NOT ONLY FOR NETLINK GENERIC.

### MORE INFORMATIONS ABOUT NETLINK PROTOCOLS AND DIFFERS NETLINK SOCKET TYPES, ATTRIBUTES NETLINK, COMMANDS
### MESSAGE TYPES AND FLAGS, STRUCTURE OF MESSAGES AND OTHERS INFORMATIONS.
### SEE DOCUMENTATION FROM KERNEL LINUX:
### https://github.com/torvalds/linux/blob/master/include/uapi/linux/genetlink.h
### https://github.com/remyoudompheng/go-netlink/blob/master/nl80211/nl80211_defs.go
### https://github.com/torvalds/linux/blob/master/include/uapi/linux/nl80211.h
### https://groups.google.com/g/golang-checkins/c/NGp_F-KVHyU
### https://medium.com/thg-tech-blog/on-linux-netlink-d7af1987f89d
### https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h 
### https://elixir.bootlin.com/linux/v4.4.109/source/include/linux/socket.h
### EXPLORE !!!

import socket
import struct
import os
import time

class nlmsg_types:
      # RTM Routing Table Management
      RTM_NEWLINK = 0x10 # DEC: 16
      RTM_DELLINK = 0x11 # DEC: 17
      RTM_GETLINK = 0x12 # DEC: 18
      RTM_SETLINK = 0x13 # DEC: 19
      RTM_NEWADDR = 0x14 # DEC: 20

      # NM Neighbour Management
      RTM_NEWNEIGH = 0x1E # DEC: 30
      RTM_DELNEIGH = 0x1F # DEC: 31
      RTM_GETNEIGH = 0x20 # DEC: 32

      # TC Traffic Control 
      TC_NEWQDISC = 0x24 # DEC: 36
      TC_DELQDISC = 0x25 # DEC: 37
      TC_NEWFILTER = 0x26 # DEC: 38
      TC_DELFILTER = 0x27 # DEC: 39
     	
      # GN Generic Netlink
      NLMSG_NOOP = 0x01 # DEC: 1
      NLMSG_ERROR = 0x02 # DEC: 2
      NLMSG_DONE = 0x03 # DEC: 3
      NLMSG_OVERRUN = 0x04 # DEC: 4

class nlmsg_flags:
      NLM_F_REQUEST = 0x01
      NLM_F_ACK = 0x04
      NLM_F_ROOT = 0x100
      NLM_F_MATCH = 0x200
      NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH 
      
def unpack_kernel_response(nlmsg):
    kernel_response = f"\nKernel Response: {nlmsg}"
    return kernel_response

def parse_nlmsg(response):
    nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack("IHHII", response[:16])
    return nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid

def socket_netlink():
    ifinfomsghdr = struct.pack("BBBBBB", 0, 0, 0, 0, 0, 0)  # PAYLOAD FOR KERNEL TO UNDERSTAND THAT IT WANTS ALL INTERFACES FOR NETWORKING OR DO OPERATION AND INTERACT WITH THE INTERFACE NETWORK HARDWARE (0 = iface type, 0 = iface state, 0 = iface flag, 0 = iface change requested) 
    nlmsghdr_len = struct.calcsize("IHHII") + len(ifinfomsghdr) # HEADER: LENGTH(4 BYTES), TYPE(2 BYTES), FLAGS(2 BYTES), SEQ(4 BYTES), PID(4 BYTES)

    # REQUEST FOR KERNEL AND ACK FOR THE KERNEL TO REPLY THAT IT RECEIVED THE MESSAGE IN NLMSG
    nlmsg = struct.pack("IHHII", nlmsghdr_len, 0x12, 0x01 | 0x04 | 0x300, 1, os.getpid()) + ifinfomsghdr # ifinfomsg and rtmsg ARE MESSAGES TO MANAGE NETWORK HARDWARE INTERFACES

    try:
       # NETLINK SOCKET BETWEEN THE PROGRAM AND KERNEL
       with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
            sock.bind((os.getpid(), 0)) # CONNECTS THE PROGRAM PROCESS TO THE NETLINK SOCKET

            # setsockopt THIS CALL SET THE LENGTH OF THE SOCKET BUFFER MEMORY FOR SENDING AND RECEIVING NLMSGs BETWEEN KERNEL 
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1000000) # 1 mb buffer for store nlmsg sent
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1000000) # 1 mb buffer for store nlmsg recv from kernel
            
            print(f"Init socket Netlink PID: {os.getpid()}")

            sock.send(nlmsg)                       
            print(unpack_kernel_response(sock.recv(65536)))

            print(parse_nlmsg(sock.recv(65536)))

    except Exception as error:
           print(f"Error {error}")
           sock.close()

if __name__ == "__main__":
   socket_netlink()
