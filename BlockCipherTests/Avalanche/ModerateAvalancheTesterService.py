from Cipher.BlockCipher import BlockCipher


class ModerateAvalancheTesterService:
    def __init__(self):
        pass

    def get_different_bits_count(self, first_plaintext : str, second_plaintext : str, key : str):
        self.__validate_inputs(first_plaintext, second_plaintext)
        blockCipher = BlockCipher()
        first_cipher_text = blockCipher.encrypt(first_plaintext, key)
        second_cipher_text = blockCipher.decrypt(second_plaintext, key)
        xored_cipher_texts_num = int(first_cipher_text, 2) ^ int(second_cipher_text, 2)
        xored_cipher_texts_str = str(bin(xored_cipher_texts_num)[2:].zfill(160))
        bit_difference = xored_cipher_texts_str.count('1')
        print(str(bit_difference) + "/80")
        return bit_difference


    def __validate_inputs(self, first_plaintext : str, second_plaintext : str):
        first_plaintext_number = int(first_plaintext, 2)
        second_plaintext_number = int(second_plaintext, 2)
        xored_input_texts_num = first_plaintext_number ^ second_plaintext_number
        xored_input_texts_str = str(bin(xored_input_texts_num)[2:].zfill(160))
        if xored_input_texts_str.count('1') != 1:
            raise Exception("for avalanche text bit differences must be 1")
