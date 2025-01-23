import hashlib

from Cipher.ProjectBlockCipher import ProjectBlockCipher
from Cipher.Exceptions.InvalidLengthException import InvalidLengthException
from Utilities.CipherUtilities import xor_two_bit_strings, binary_to_hex, text_to_binary, xor_two_hex_strings, \
    hex_to_binary
import matplotlib.pyplot as plt
import numpy as np


class StrictAvalancheTesterService:
    def __init__(self, plain_texts_file_path, key, cipher_rounds, feistel_rounds):
        self.file_path = plain_texts_file_path
        self.key = ''.join(format(ord(char), '08b') for char in key)
        self.cipher_round = cipher_rounds
        self.feistel_round = feistel_rounds

    def do_sac_test(self, bits_count):
        cipher = ProjectBlockCipher(self.cipher_round, self.feistel_round)
        plain_texts = self.__read_file_words(bits_count)
        cipher_texts = []
        plain_texts_count = len(plain_texts)
        for i in range(0, plain_texts_count):
            cipher_texts.append(self.__get_cipher_version(cipher, plain_texts[i], self.key))
        sac_matrix = {i: [0] * bits_count for i in range(bits_count)}
        for plain_text in plain_texts:
            binary_text = plain_text
            print(binary_text)
            for index in range(0, len(binary_text)):
                text_version = self.__get_input_version(binary_text, index)
                print(str(index) + " : "+ text_version)
                cipher_version = self.__get_cipher_version(cipher, text_version, bits_count)
                xored_cipheres = xor_two_bit_strings(cipher_texts[index], cipher_version, bits_count)
                sac_matrix[index] = self._add_cipher_version_to_sac_matrix(sac_matrix[index], xored_cipheres)
        abundance = {}
        for list_value in sac_matrix.values():
            for value in list_value:
                if value not in abundance:
                    abundance[value] = 1
                else:
                    abundance[value] = abundance[value] + 1

        keys = list(abundance.keys())
        keys.sort()
        sd = {i: abundance[i] for i in keys}
        plot_keys = np.array(list(sd.keys()))
        plot_values = np.array(list(sd.values()))
        plt.plot(plot_keys, plot_values, label="نمودار فراوانی", color='blue', marker ='o')
        plt.show()
        return sac_matrix, sd

    def __get_cipher_version(self, cipher, text, bits_count):
        if bits_count == 160:
            return cipher.encrypt(text, self.key)
        final_key = hashlib.sha256(self.key.encode()).hexdigest()
        return hex_to_binary(cipher.feistel_function(binary_to_hex(text), final_key))

    def _add_cipher_version_to_sac_matrix(self, sac_version, cipher_version):
        str_num_list = [int(char) for char in cipher_version]
        return [sac_version[i] + str_num_list[i] for i in range(len(sac_version))]

    def __get_input_version(self, plain_text_binary, index):
        return plain_text_binary[:index] + self.__flip_bit(plain_text_binary[index]) + plain_text_binary[index + 1:]

    def __flip_bit(self, bit_char):
        if bit_char == '1':
            return '0'
        else:
            return '1'

    def __read_file_words(self, bits_count):
        words = []
        with open(self.file_path, 'r', encoding='ascii') as file:
            for line in file:
                word = line.strip()
                if len(word) != (bits_count / 8):
                    raise InvalidLengthException("invalid plain text length")
                words.append(text_to_binary(word))
        return words