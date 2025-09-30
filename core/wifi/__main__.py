# for tests

from . import *
    
def main():
    from .l2.ieee802_11.ieee802_11 import IEEE802_11
    from ..common.filter_engine import apply_filters

    eapol_msg1 = bytes.fromhex('''
00001a002f48000062b2270e00000000
00026c09a000c70000008802ca0006ab
f1d631165c628b80838a5c628b80838a
00000000aaaa03000000888e01030075
02008a001000000000000000015de91b
37c74d1ba0a8919d20c971e890a14da3
b29f979e0ca73323404d9f4366000000
00000000000000000000000000000000
00000000000000000000000000000000
000000000000000000000000000016dd
14000fac0413db5dd8d7b4af25317703
399b3e3016
''')
    eapol_msg2 = bytes.fromhex('''
00001a002f48000045ce270e00000000
00026c09a000df00000088013a015c62
8b80838a06abf1d631165c628b80838a
00000600aaaa03000000888e01030075
02010a00000000000000000001db741d
48ed9b31f27f7c6c654844fb57ef5c69
ca8c57b5843df21f319d106ab3000000
00000000000000000000000000000000
000000000000000000000000002cdadf
ff17d404500929a37d848e7f3a001630
140100000fac040100000fac04010000
0fac028000
''' )

    parsed_frame = IEEE802_11.frames_parser(eapol_msg2)
    store_filter_result, frame_filter_result = apply_filters("Body.EAPOL", "Body.LLC.Type, MACHeader.BSSID", parsed_frame) 
    if store_filter_result:
        print(parsed_frame, frame_filter_result)

    #L2.IEEE802_11.sniff("L2", "IEEE802.11", sock, "wlan1")

    #from scapy.all import *
    #packet = Radiotap(eapol_msg2)
    #wrpcap("eapol_test.pcap", [packet])
    #print("Arquivo pcap criado: eapol_test.pcap")

if __name__ == "__main__":
   main()
