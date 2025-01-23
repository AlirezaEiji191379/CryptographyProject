def xor_two_bit_strings(string1, string2, zfill):
    first_string_number = int(string1, 2)
    second_string_number = int(string2, 2)
    return str(bin(first_string_number ^ second_string_number)[2:]).zfill(zfill)

def xor_two_hex_strings(string1, string2, zfill):
    bin_string1 = hex_to_binary(string1)
    bin_string2 = hex_to_binary(string2)
    binary_xor_result = xor_two_bit_strings(bin_string1, bin_string2, zfill * 4)
    return binary_to_hex(binary_xor_result)

def binary_to_hex(binary_str):
    return ''.join([hex(int(binary_str[i:i + 4], 2))[2:] for i in range(0, len(binary_str), 4)])

def hex_to_binary(hex_str):
    return ''.join([bin(int(char, 16))[2:].zfill(4) for char in hex_str])

def binary_to_text(binary_str):
    return ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])

def text_to_binary(text):
    return ''.join(format(ord(i), '08b') for i in text)