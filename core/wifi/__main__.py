# for tests

from . import *
    
def main():
    from .l2.ieee802_11.ieee802_11 import IEEE802_11
    from ..common.filter_engine import apply_filters
    from ..common.useful_functions import MacVendorResolver

    mac_vendor_resolver = MacVendorResolver("./core/common/mac-vendors-export.json")

    parsed_frame = IEEE802_11.frames_parser(eapol_msg1, mac_vendor_resolver)
    #store_filter, display_result = apply_filters("mac_hdr.fc.type == 2 and mac_hdr.mac_src.mac in ('06:ab:f1:d6:31:16', '5c:62:8b:80:83:8a') and mac_hdr.mac_dst.mac in ('06:ab:f1:d6:31:16', '5c:62:8b:80:83:8a') and mac_hdr.bssid.mac == '5c:62:8b:80:83:8a' and body.llc.type == '0x888e' and body.eapol", "mac_hdr, body", parsed_frame)
    store_filter, display_result = apply_filters("mac_hdr.fc.type == 2 and mac_hdr.mac_src.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.mac_dst.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.bssid == 'aa:bb:cc:dd:ee:ff' and llc.type == '0x888e' and body.eapol", "mac_hdr, body", parsed_frame)
    store_filter, display_result = apply_filters("mac_hdr.fc.type == 2 and mac_hdr.mac_src.mac in ('06:ab:f1:d6:31:16', '5c:62:8b:80:83:8a') and mac_hdr.mac_dst.mac in ('06:ab:f1:d6:31:16', '5c:62:8b:80:83:8a')", "mac_hdr, body", parsed_frame)
    if store_filter:
        print(display_result)
    print(parsed_frame)
    #for k, v in parsed_frame.items():
     #   print(f"{k} => {v}\n")
    #if store_filter_result:
        #print(frame_filter_result)
        #for k, v in frame_filter_result.items():
         #   for kk, vv in v.items():
          #      print(vv)
           #     print()

if __name__ == "__main__":
    main()
