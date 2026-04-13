from core.common.function_utils import setup_logging
from core.common.filter_engine import apply_filters
from core.common.parser_utils import iter_packets_from_json
from core.layers.registry import (get_parser, get_dlt_value)
import logging

logger = logging.getLogger(__name__)

def parser_test(dlt: str, input_filename: str, output_filename: str = None):
    """
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

    """
    parser = get_parser(dlt)

    result = {}

    try:
        i = 1
        for cleaned, raw_bytes in iter_packets_from_json(input_filename):
            result[i] = parser(raw_bytes)
            result["raw"] = cleaned
            result["frame_counter"] = i
    except Exception as e:
        logger.critical(f"Unexpected error: {e}")

    print(result)
def main():
    parser_test("DLT_IEEE802_11_RADIO", "/home/gus/Documents/framesniff/core/tests/frames.json")

if __name__ == "__main__":
    main()
