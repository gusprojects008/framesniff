# for tests

from . import *
    
def main():
    from .l2.ieee802_11.ieee802_11 import IEEE802_11
    from ..common.filter_engine import apply_filters
    from ..common.useful_functions import MacVendorResolver

    mac_vendor_resolver = MacVendorResolver("./core/common/mac-vendors-export.json")

    parsed_frame = IEEE802_11.frames_parser(probe_response, mac_vendor_resolver)
    store_filter_result, frame_filter_result = apply_filters("", "rt_hdr, mac_hdr, body, fcs", parsed_frame) 
    #print(parsed_frame)
    if store_filter_result:
        print(frame_filter_result)
        #for k, v in frame_filter_result.items():
         #   for kk, vv in v.items():
          #      print(vv)
           #     print()

if __name__ == "__main__":
    main()
