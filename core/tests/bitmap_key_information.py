key_information = 0x13ca

bitmap_key_information = {
  "Key descriptor version": (0, 2),
  "Key type": (3, 1),
  "Key index": (4, 2),
  "Install": (6, 1),
  "Key ACK": (7, 1),
  "Key MIC": (8, 1),
  "Secure": (9, 1),
  "Error": (10, 1),
  "Request": (11, 1),
  "Encrypted key data": (12, 1),
  "SMK message": (13, 1)
}

flags_key_information = {
  "Key descriptor version": {1: "HMAC-MD5 (WPA)", 2: "AES/HMAC-SHA1 (WPA2/WPA3)"},
  "Key type": {0: "Group (GTK)", 1: "Pairwise (PTK)"},
}

def parser_bitmap_key_information(key_information, key_information_list):
    key_information_result = {}
    for key, (bit_position, bits_len) in key_information_list.items():
        bits_mask = (1 << bits_len) - 1
        value = (key_information >> bit_position) & bits_mask
        if key in flags_key_information and value in flags_key_information[key]:
           key_information_result[key] = f"{value} {flags_key_information[key][value]}"
        else:
            key_information_result[key] = value

    return key_information_result

print(parser_bitmap_key_information(key_information, bitmap_key_information))

"""
def parser_bitmaps(bitmap_value, bitmap_list):
    for key, value in bitmap_list:
        if  == 
"""

# 0001001111001010
# 2 == 010

# 0001001111001010

#0010
#0001
#0000
# 
