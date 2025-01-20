def xor_two_bit_strings(string1, string2):
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(string1, string2))