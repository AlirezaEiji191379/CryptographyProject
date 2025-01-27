from Ciphers.ProjectBlockCipher import ProjectBlockCipher
from Utilities.CipherUtilities import xor_two_bit_strings


class ModerateAvalancheTesterService:
    def __init__(self):
        pass

    def get_different_bits_count(self, first_plaintext : str, second_plaintext : str, key : str):
        self.__validate_inputs(first_plaintext, second_plaintext)
        blockCipher = ProjectBlockCipher()
        first_cipher_text = blockCipher.encrypt(first_plaintext, key)
        second_cipher_text = blockCipher.encrypt(second_plaintext, key)
        xored_cipher_texts_str = xor_two_bit_strings(first_cipher_text, second_cipher_text, 160)
        bit_difference = xored_cipher_texts_str.count('1')
        print(str(bit_difference) + "/80")
        return bit_difference


    def __validate_inputs(self, first_plaintext : str, second_plaintext : str):
        xored_input_texts_str = xor_two_bit_strings(first_plaintext, second_plaintext, 160)
        if xored_input_texts_str.count('1') != 1:
            raise Exception("for avalanche text bit differences must be 1")
