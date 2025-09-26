import socket 

# OPERATION SHIF LEFT BITWISE: << SHIFT THE BITS OF A NUMBER TO LEFT, FROM A SPECIFIC NUMBER.
# EXEMPLE:
number_x = 12
number_shift = 2

shift_left = number_x << number_shift
shift_right = number_x >> number_shift

number_x_bin = bin(number_x)[2:].zfill(8)
number_shift_bin = bin(number_shift)[2:].zfill(8)

print(f"{number_x} IS {number_x_bin}\n{number_shift} IS  {number_shift_bin}")
print(f"\nRESULT SHIFT RIGHT OPERATION WITH:\n")

print(f"{number_x_bin} == {number_x}\n{number_shift_bin} == {number_shift} is movement number\n")
print("Operation Shift Right,  result:")
print(f"======>>\n{number_x_bin}\n{number_shift_bin}\n{bin(shift_right)[2:].zfill(8)} THIS IS A OPERATION SHIFT RIGHT >>\n\n")

print(f"RESULT SHIFT LEFT OPERATION WITH:\n")

print(f"{number_x_bin} == {number_x}\n{number_shift_bin} == {number_shift} is movement number\n")
print("Operation Shift Left,  result:")
print(f"<<======\n{number_x_bin}\n{number_shift_bin}\n{bin(shift_left)[2:].zfill(8)} THIS IS A OPERATION SHIFT LEFT >>\n")

# SIGNED BITS: OF A SPECIFIC NUMBER OF BITS, ONE BIT IS USED FOR REPRESENT THE SIGNAL POSITIVE OR NEGATIVE OF A VALUE BINARY, LIKE THIS
# UNSIGNED BITS: USE ALL BITS FOR REPRESENT A VALUE THE NUMBER, WITHOUT SIGN BIT
# socket.hton() CONVERT 16 bits short of integer IN ORDER OF NETWORK BYTES(BIG ENDIAN), AND THEN STORED THE MOST BIT SIGNIFICANT
# THIS ORDER OF DATA NETWORK IS USED FOR STANDARDIZE THE DATA EXCHANGE, AND ENSURE THAT THE DATAS CAN BE INTERPRETED BY DIFFERENTS SYSTEMS
def own_htons_func(int_data):
    print("htons function, transforming int in value correct for network:")
    print(f"VALUE: {int_data} IN BINARY: {bin(int_data)[2:].zfill(8)}\nBINARY TO OPERATION bit-to-bit and: {bin(0x77)[2:].zfill(8)}")

    # OPERATION BIT FOR BIT (AND) WITH 0xff, AFTER OPERATION (SHIFT LEFT) WITH 8, AND WITH THE RESULT, DO OPERATION (OR) WITH RESULT
    # OF OPERATION SHIFT RIGHT WITH 8 AND WITH RESULT DO OPERATION (AND) WITH 0Xff 
    order_network = ((int_data & 0xff) << 8) | ((int_data >> 8) & 0xff) # 0xff IS 11111111 in binary, IDEAL FOR DOING A bit-by-bit and OPERATION

    print(f"Result operation bit-by-bit AND: {order_network} => VALUE RESULT IN BINARY: {bin(order_network)[2:].zfill(8)}")

print()
int_data_val = 123
own_htons_func(int_data_val)
print('\n')

print("USING socket.htons(): ")
sock_htons = socket.htons(int_data_val)
print(sock_htons)
