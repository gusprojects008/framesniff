import socket

ifaces = socket.if_nameindex()

iface_index_pername = socket.if_nametoindex("wlan0")

print(iface_index_pername)
