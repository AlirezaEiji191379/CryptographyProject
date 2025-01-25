from Cipher.Exceptions.InvalidLengthException import InvalidLengthException
from Utilities.CipherUtilities import xor_two_bit_strings, xor_two_hex_strings, hex_to_binary, binary_to_hex, \
    binary_to_text, text_to_binary
import hashlib
import numpy as np


class ProjectBlockCipher:
    def __init__(self, block_rounds=None, f_rounds=None):
        self.sbox_dict = {
    "00": "70", "01": "82", "02": "2c", "03": "ec", "04": "b3", "05": "27", "06": "c0", "07": "e5",
    "08": "e4", "09": "85", "0a": "57", "0b": "35", "0c": "ea", "0d": "0c", "0e": "ae", "0f": "41",
    "10": "23", "11": "ef", "12": "6b", "13": "93", "14": "45", "15": "19", "16": "a5", "17": "21",
    "18": "ed", "19": "0e", "1a": "4f", "1b": "4e", "1c": "1d", "1d": "65", "1e": "92", "1f": "bd",
    "20": "86", "21": "b8", "22": "af", "23": "8f", "24": "7c", "25": "eb", "26": "1f", "27": "ce",
    "28": "3e", "29": "30", "2a": "dc", "2b": "5f", "2c": "5e", "2d": "c5", "2e": "0b", "2f": "1a",
    "30": "a6", "31": "e1", "32": "39", "33": "ca", "34": "d5", "35": "47", "36": "5d", "37": "3d",
    "38": "d9", "39": "01", "3a": "5a", "3b": "d6", "3c": "51", "3d": "56", "3e": "6c", "3f": "4d",
    "40": "8b", "41": "0d", "42": "9a", "43": "66", "44": "fb", "45": "cc", "46": "b0", "47": "2d",
    "48": "74", "49": "12", "4a": "2b", "4b": "20", "4c": "f0", "4d": "b1", "4e": "84", "4f": "99",
    "50": "df", "51": "4c", "52": "cb", "53": "c2", "54": "34", "55": "7e", "56": "76", "57": "05",
    "58": "6d", "59": "b7", "5a": "a9", "5b": "31", "5c": "d1", "5d": "17", "5e": "04", "5f": "d7",
    "60": "14", "61": "58", "62": "3a", "63": "61", "64": "de", "65": "1b", "66": "11", "67": "1c",
    "68": "32", "69": "0f", "6a": "9c", "6b": "16", "6c": "53", "6d": "18", "6e": "f2", "6f": "22",
    "70": "fe", "71": "44", "72": "cf", "73": "b2", "74": "c3", "75": "b5", "76": "7a", "77": "91",
    "78": "24", "79": "08", "7a": "e8", "7b": "a8", "7c": "60", "7d": "fc", "7e": "69", "7f": "50",
    "80": "aa", "81": "d0", "82": "a0", "83": "7d", "84": "a1", "85": "89", "86": "62", "87": "97",
    "88": "54", "89": "5b", "8a": "1e", "8b": "95", "8c": "e0", "8d": "ff", "8e": "64", "8f": "d2",
    "90": "10", "91": "c4", "92": "00", "93": "48", "94": "a3", "95": "f7", "96": "75", "97": "db",
    "98": "8a", "99": "03", "9a": "e6", "9b": "da", "9c": "09", "9d": "3f", "9e": "dd", "9f": "94",
    "a0": "87", "a1": "5c", "a2": "83", "a3": "02", "a4": "cd", "a5": "4a", "a6": "90", "a7": "33",
    "a8": "73", "a9": "67", "aa": "f6", "ab": "f3", "ac": "9d", "ad": "7f", "ae": "bf", "af": "e2",
    "b0": "52", "b1": "9b", "b2": "d8", "b3": "26", "b4": "c8", "b5": "37", "b6": "c6", "b7": "3b",
    "b8": "81", "b9": "96", "ba": "6f", "bb": "4b", "bc": "13", "bd": "be", "be": "63", "bf": "2e",
    "c0": "e9", "c1": "79", "c2": "a7", "c3": "8c", "c4": "9f", "c5": "6e", "c6": "bc", "c7": "8e",
    "c8": "29", "c9": "f5", "ca": "f9", "cb": "b6", "cc": "2f", "cd": "fd", "ce": "b4", "cf": "59",
    "d0": "78", "d1": "98", "d2": "06", "d3": "6a", "d4": "e7", "d5": "46", "d6": "71", "d7": "ba",
    "d8": "d4", "d9": "25", "da": "ab", "db": "42", "dc": "88", "dd": "a2", "de": "8d", "df": "fa",
    "e0": "72", "e1": "07", "e2": "b9", "e3": "55", "e4": "f8", "e5": "ee", "e6": "ac", "e7": "0a",
    "e8": "36", "e9": "49", "ea": "2a", "eb": "68", "ec": "3c", "ed": "38", "ee": "f1", "ef": "a4",
    "f0": "40", "f1": "28", "f2": "d3", "f3": "7b", "f4": "bb", "f5": "c9", "f6": "43", "f7": "c1",
    "f8": "15", "f9": "e3", "fa": "ad", "fb": "f4", "fc": "77", "fd": "c7", "fe": "80", "ff": "9e"}
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
        

        #xor whitening key
        plain_text =  self.__cipher_key_whitening(key,plain_text)

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
        cipher_text_binary = self.__cipher_key_whitening(key,cipher_text_binary)
        return cipher_text_binary

    def __validate_inputs(self, text: str, key: str):
        if len(text) > 160:
            raise InvalidLengthException("The length of the text must be less than 160 bits.")

        if len(key) != 160:
            raise InvalidLengthException("The length of the key must be 160 bits.")

    def __cipher_key_whitening(self, key: str,plain_text_bin: str):
        #xor_two_bit_strings(hashlib.sha256(input_key.encode()).hexdigest(),plain_text_hex,160)
        round_binary = str(bin(0))
        input_key = round_binary + key
        sha256_key = (hashlib.sha256(input_key.encode()).hexdigest())
        sha256_key1 = hex_to_binary(sha256_key)[:160]
        # print(len(sha256_key1))
        # print(len(plain_text_bin))
        whitened = xor_two_bit_strings(plain_text_bin,sha256_key1,160)

        return whitened

    def __cipher_key_scheduling(self, key: str, is_enc: bool = True):
        round_keys = []
        for i in range(1, self.block_cipher_rounds+1):
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
        r = 20
        b = len(key) // 4
        c = (r + 1) * 2
        S = [0] * c
        P = 0xB7E15163
        Q = 0x9E3779B9
        S[0] = P
        for i in range(1, c):
            S[i] = (S[i - 1] + Q) & 0xFFFFFFFF
        T = [0] * (b)
        for i in range(b):
            T[i] = int(hex_to_binary(key[i * 4:(i + 1) * 4]), 2)
        i = 0
        j = 0
        A = B = 0
        for k in range(3 * max(b, c)):
            A = S[i] = (S[i] + A + B) & 0xFFFFFFFF
            B = T[j] = (T[j] + A + B) & 0xFFFFFFFF
            i = (i + 1) % c
            j = (j + 1) % b

        for i in range(0, len(S)):
            S[i] = binary_to_hex(str(bin(S[i]))[2:].zfill(32))

        result_sub_keys = []
        for i in range(0, 24, 4):
            result_sub_keys.append(S[i] + S[i + 1] + S[i + 2] + S[i + 3])

        return result_sub_keys[0:self.f_rounds]

    # def __feistel_function_key_schedule(self, key):
    #     all_keys = []
    #     key_binary = hex_to_binary(key)
    #     for i in range(0, self.f_rounds):
    #         x = str(bin(i)[2:]) + key_binary
    #         sha256_key = str(hashlib.sha256(x.encode()).hexdigest())[0:32]
    #         all_keys.append(sha256_key)
    #     return all_keys

    # this is from s0 sbox of serpent
    def __substitution(self, byte_str: str) -> str:
        # msb_nibble = byte_str[0]  # left side
        # lsb_nibble = byte_str[1]  # right side
        # for i in range(0, 3):
        #     sbox_result = self.sbox_dict[lsb_nibble]
        #     temp = xor_two_hex_strings(msb_nibble, sbox_result, 1)
        #     msb_nibble = lsb_nibble
        #     lsb_nibble = temp
        # return lsb_nibble + msb_nibble  # the last round should be flipped
        return self.sbox_dict[byte_str]

    # this is the rijndeal shift rows differed
    def __shift_rows(self, state_matrix: list) -> list:
        for i in range(3,0,-1):
            state_matrix[3-i] = state_matrix[3-i][i:] + state_matrix[3-i][:i] # 1st row: 1, 2nd: 2, 3rd:3 4rd: 0
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
