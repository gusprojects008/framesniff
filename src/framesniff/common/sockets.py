import socket

def create_raw_socket(ifname):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((ifname, 0))
    return sock
