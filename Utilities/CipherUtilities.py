def xor_two_bit_strings(string1, string2):
    first_string_number = int(string1, 2)
    second_string_number = int(string2, 2)
    return str(bin(first_string_number ^ second_string_number)[2:]).zfill(160)
