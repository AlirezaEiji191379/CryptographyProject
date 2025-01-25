from Cipher.Exceptions.InvalidLengthException import InvalidLengthException
from Utilities.CipherUtilities import xor_two_bit_strings, xor_two_hex_strings, hex_to_binary, binary_to_hex, \
    binary_to_text, text_to_binary
import hashlib
import numpy as np


class ProjectBlockCipher:
    def __init__(self, block_rounds=None, f_rounds=None):
        self.sbox_dict = {'0': '3', '1': '8', '2': 'f', '3': '1', '4': 'a',
                          '5': '6', '6': '5', '7': 'b', '8': 'e', '9': 'd',
                          'a': '4', 'b': '2', 'c': '7', 'd': '0', 'e': '9', 'f': 'c'}
        if block_rounds is None:
            self.block_cipher_rounds = 9
        else:
            self.block_cipher_rounds = block_rounds

        if f_rounds is None:
            self.f_rounds = 6
        else:
            self.f_rounds = f_rounds

    def encrypt(self, plain_text: str, key: str, is_enc: bool = True) -> str:
        self.__validate_inputs(plain_text, key)
        round_keys = self.__cipher_key_scheduling(key, is_enc)
        plain_text_hex = binary_to_hex(plain_text)
        msb_hex = plain_text_hex[:20]
        lsb_hex = plain_text_hex[20:]
        for i in range(0, self.block_cipher_rounds):
            fiestel_input_hex = lsb_hex + round_keys[i][0:12]
            feistel_result = self.feistel_function(fiestel_input_hex, round_keys[i])[0:20]
            temp = xor_two_hex_strings(msb_hex, feistel_result, 20)
            msb_hex = lsb_hex
            lsb_hex = temp
        cipher_text_hex = lsb_hex + msb_hex  # because in the last round we do not want replacing msb and lsb
        cipher_text_binary = hex_to_binary(cipher_text_hex)
        return cipher_text_binary

    def __validate_inputs(self, text: str, key: str):
        if len(text) > 160:
            raise InvalidLengthException("The length of the text must be less than 160 bits.")

        if len(key) != 160:
            raise InvalidLengthException("The length of the key must be 160 bits.")

    def __cipher_key_scheduling(self, key: str, is_enc: bool = True):
        round_keys = []
        for i in range(0, self.block_cipher_rounds):
            round_binary = str(bin(i)[2:])
            input_key = round_binary + key
            sha256_key = str(hashlib.sha256(input_key.encode()).hexdigest())
            round_keys.append(sha256_key)
        if not is_enc:
            round_keys.reverse()
        return round_keys

    def feistel_function(self, input_hex, f_round_key_hex):
        key_hex = f_round_key_hex[12:]  # the total key for the f function that needs key schedule
        all_rounds_keys = self.__feistel_function_key_schedule(key_hex)
        for i in range(0, self.f_rounds):
            added_key_hex = self.__add_key(input_hex, all_rounds_keys[i])
            substituted_bytes = ''
            for t in range(0, len(added_key_hex), 2):
                substituted_bytes = substituted_bytes + self.__substitution(added_key_hex[t] + added_key_hex[t + 1])
            state_matrix = self.__fill_state_matrix(substituted_bytes)
            shifted_state_matrix = self.__shift_rows(state_matrix)
            input_hex = self.__mix_column(shifted_state_matrix)
        return input_hex

    def __feistel_function_key_schedule(self, key):
        all_keys = []
        key_binary = hex_to_binary(key)
        for i in range(0, self.f_rounds):
            x = str(bin(i)[2:]) + key_binary
            sha256_key = str(hashlib.sha256(x.encode()).hexdigest())[0:32]
            all_keys.append(sha256_key)
        return all_keys

    # this is from s0 sbox of serpent
    def __substitution(self, byte_str: str) -> str:
        msb_nibble = byte_str[0]  # left side
        lsb_nibble = byte_str[1]  # right side
        for i in range(0, 3):
            sbox_result = self.sbox_dict[lsb_nibble]
            temp = xor_two_hex_strings(msb_nibble, sbox_result, 1)
            msb_nibble = lsb_nibble
            lsb_nibble = temp
        return lsb_nibble + msb_nibble  # the last round should be flipped

    # this is exactly the rijndeal shift rows
    def __shift_rows(self, state_matrix: list) -> list:
        for i in range(3,-1,-1):
            state_matrix[3-i] = state_matrix[3-i][i:] + state_matrix[3-i][:i] # 1,2,3,0
        return state_matrix

    # this is exactly the rijndeal mix columns
    def __mix_column(self, state_matrix: list) -> list:
        if len(state_matrix) != 4:
            raise InvalidLengthException("The length of the state matrix must be 4 lists.")
        transposed_matrix = np.array(state_matrix).T
        result_state_matrix = []
        for i in range(0, 4):
            vector = transposed_matrix[i]
            x, y, z, t = int(vector[0], 16), int(vector[1], 16), int(vector[2], 16), int(vector[3], 16)
            new_vector = []
            new_vector.append(
                str(hex(self.__mul_gf(x, 2) ^ self.__mul_gf(y, 3) ^ self.__mul_gf(z, 1) ^ self.__mul_gf(t, 1)))[
                2:].zfill(2))
            new_vector.append(
                str(hex(self.__mul_gf(x, 1) ^ self.__mul_gf(y, 2) ^ self.__mul_gf(z, 3) ^ self.__mul_gf(t, 1)))[
                2:].zfill(2))
            new_vector.append(
                str(hex(self.__mul_gf(x, 1) ^ self.__mul_gf(y, 1) ^ self.__mul_gf(z, 2) ^ self.__mul_gf(t, 3)))[
                2:].zfill(2))
            new_vector.append(
                str(hex(self.__mul_gf(x, 3) ^ self.__mul_gf(y, 1) ^ self.__mul_gf(z, 1) ^ self.__mul_gf(t, 2)))[
                2:].zfill(2))
            result_state_matrix.append(new_vector)
        result_matrix = np.array(result_state_matrix).tolist()
        result_text = ""
        for i in range(0, 4):
            for j in range(0, 4):
                result_text += str(result_matrix[i][j])
        return result_text

    def __fill_state_matrix(self, input_text: str):
        if len(input_text) != 32:
            raise InvalidLengthException("The length of the input bits must be 128 bits.")

        hex_pairs = [input_text[i:i + 2] for i in range(0, len(input_text), 2)]

        return (np.array(hex_pairs).reshape(4, 4).T).tolist()

    def __add_key(self, input_hex: str, keyhex: str):
        if len(input_hex) != 32 and len(keyhex) != 32:
            raise InvalidLengthException("The length of the input hex and key must be 128 bits.")
        result_added_key_hex = ''
        for i in range(0, 32, 2):
            first_num = int(input_hex[i] + input_hex[i + 1], 16)
            second_num = int(keyhex[i] + keyhex[i + 1], 16)
            result = (first_num + second_num) % 256
            result_added_key_hex = result_added_key_hex + binary_to_hex(str(bin(result)[2:].zfill(8)))
        return result_added_key_hex

    def __mul_gf(self, a, b):
        if b == 1:
            return a
        tmp = (a << 1) & 0xff
        if b == 2:
            return tmp if a < 128 else tmp ^ 0x1b
        if b == 3:
            return self.__mul_gf(a, 2) ^ a
