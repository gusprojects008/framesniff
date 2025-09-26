import struct

little_endian_val = struct.pack('<hhhh', 1, 2, 3, 4)
big_endian_val = struct.pack('>hhhh', 1, 2, 3, 4)

print(f"THE LEAST SIGNIFICANT BIT COME FIRST IN LITTLE ENDIAN '<': {little_endian_val} {struct.unpack('<hhhh', little_endian_val)}\nTHE BIT MOST SIGNIFICANT COME FIRST IN BIG ENDIAN '>': {big_endian_val} {struct.unpack('>hhhh', big_endian_val)}")
