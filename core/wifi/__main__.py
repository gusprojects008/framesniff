# for tests

from . import *
    
def main():
    from .l2.ieee802_11.ieee802_11 import IEEE802_11
    from ..common.filter_engine import apply_filters

    parsed_frame = IEEE802_11.frames_parser(LB)
    store_filter_result, frame_filter_result = apply_filters("", "fcs", parsed_frame) 
    #print(parsed_frame)
    if store_filter_result:
        print(frame_filter_result)
        #for k, v in frame_filter_result.items():
         #   for kk, vv in v.items():
          #      print(vv)
           #     print()

if __name__ == "__main__":
    main()
