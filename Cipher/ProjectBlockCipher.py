from Cipher.Exceptions.InvalidLengthException import InvalidLengthException
from Utilities.CipherUtilities import xor_two_bit_strings, xor_two_hex_strings
import hashlib
import numpy as np


class ProjectBlockCipher:
    def __init__(self):
        self.sbox_dict = {'0' : '3', '1' : '8', '2' : 'f', '3' : '1', '4' : 'a',
                          '5' : '6', '6' : '5', '7' : 'b', '8' : 'e', '9' : 'd',
                          'a' : '4', 'b' : '2', 'c' : '7', 'd' : '0', 'e' : '9', 'f' : 'c'}
        self.block_cipher_rounds = 32
        self.f_rounds = 5

    def encrypt(self, plain_text : str, key : str) -> str:
        self.__validate_inputs(plain_text, key)
        pass

    def decrypt(self, cipher_text : str, key : str) -> str:
        self.__validate_inputs(cipher_text, key)
        pass

    def __validate_inputs(self, text: str, key : str):
        if len(text) > 160:
            raise InvalidLengthException("The length of the text must be less than 160 bits.")

        if len(key) != 160:
            raise InvalidLengthException("The length of the key must be 160 bits.")


    def __cipher_key_scheduling(self, key : str, is_enc : bool = True):
        round_keys = []
        for i in range(0, self.block_cipher_rounds):
            round_binary = bin(i)[2:]
            input_key = round_binary + key
            sha256_key = hashlib.sha256(input_key.encode()).hexdigest()
            round_keys.append(sha256_key)
        if is_enc == False:
            round_keys.reverse()
        return round_keys


    def __feistel_function_rounds(self, lsb_hex, round_key_hex):
        pass

    # this is from s0 sbox of serpent
    def __substitution(self, byte_str : str) -> str:
        msb_nibble = byte_str[0] # left side
        lsb_nibble = byte_str[1] # right side
        for i in range(0, 3):
            sbox_result = self.sbox_dict[lsb_nibble]
            temp = xor_two_hex_strings(msb_nibble, sbox_result, 2)
            msb_nibble = lsb_nibble
            lsb_nibble = temp
        return msb_nibble + lsb_nibble

    # this is exactly the rijndeal shift rows
    def __shift_rows(self, state_matrix : list) -> list:
        for i in range(1, 4):
            state_matrix[i] = state_matrix[i][i:] + state_matrix[i][:i]
        return state_matrix

    # this is exactly the rijndeal mix columns
    def __mix_column(self, state_matrix : list) -> list:
        if len(state_matrix) != 4:
            raise InvalidLengthException("The length of the state matrix must be 4 lists.")
        transposed_matrix = np.array(state_matrix).T
        result_state_matrix = []
        for i in range(0, 4):
            vector = transposed_matrix[i]
            x, y, z, t = int(vector[0], 16), int(vector[1], 16), int(vector[2], 16), int(vector[3], 16)
            new_vector = []
            new_vector.append(str(hex(self.__mul_gf(x, 2) ^ self.__mul_gf(y, 3) ^ self.__mul_gf(z, 1) ^ self.__mul_gf(t, 1)))[2:].zfill(2))
            new_vector.append(str(hex(self.__mul_gf(x, 1) ^ self.__mul_gf(y, 2) ^ self.__mul_gf(z, 3) ^ self.__mul_gf(t, 1)))[2:].zfill(2))
            new_vector.append(str(hex(self.__mul_gf(x, 1) ^ self.__mul_gf(y, 1) ^ self.__mul_gf(z, 2) ^ self.__mul_gf(t, 3)))[2:].zfill(2))
            new_vector.append(str(hex(self.__mul_gf(x, 3) ^ self.__mul_gf(y, 1) ^ self.__mul_gf(z, 1) ^ self.__mul_gf(t, 2)))[2:].zfill(2))
            result_state_matrix.append(new_vector)
        return np.array(result_state_matrix).T.tolist()

    def __fill_state_matrix(self, input_text : str):
        if len(input_text) != 32:
            raise InvalidLengthException("The length of the input bits must be 128 bits.")

        hex_pairs = [input_text[i:i + 2] for i in range(0, len(input_text), 2)]

        return (np.array(hex_pairs).reshape(4, 4).T).tolist()

    def __add_key(self, input_hex : str, keyhex : str):
        if len(input_hex) != 32 and len(keyhex) != 32:
            raise InvalidLengthException("The length of the input hex and key must be 128 bits.")
        return xor_two_hex_strings(input_hex, keyhex, 32)

    def __mul_gf(self, a, b):
        if b == 1:
            return a
        tmp = (a << 1) & 0xff
        if b == 2:
            return tmp if a < 128 else tmp ^ 0x1b
        if b == 3:
            return self.__mul_gf(a, 2) ^ a