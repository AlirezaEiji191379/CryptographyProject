import hashlib

from Ciphers.ProjectBlockCipher import ProjectBlockCipher
from Ciphers.Exceptions.InvalidLengthException import InvalidLengthException
from Utilities.CipherUtilities import xor_two_bit_strings, binary_to_hex, text_to_binary, xor_two_hex_strings, \
    hex_to_binary
import matplotlib.pyplot as plt
import numpy as np


class StrictAvalancheTesterService:
    def __init__(self, plain_texts_file_path, key, cipher_rounds, feistel_rounds, block_cipher_size):
        self.file_path = plain_texts_file_path
        self.block_cipher_size = block_cipher_size
        if self.block_cipher_size != 160:
            self.key = str(hashlib.sha256(key.encode()).hexdigest())
        else:
            self.key = ''.join(format(ord(char), '08b') for char in key)
        self.cipher_round = cipher_rounds
        self.feistel_round = feistel_rounds

    def do_sac_test(self):
        cipher = ProjectBlockCipher(self.cipher_round, self.feistel_round)
        sac_matrix = {i: [0] * self.block_cipher_size for i in range(self.block_cipher_size)}
        with open(self.file_path, 'r', encoding='ascii') as file:
            plain_text = ''
            key_binary = hex_to_binary(self.key[0:12])
            line_index = 0
            for line in file:
                print(line_index)
                word = line.strip()
                if self.block_cipher_size != 160:
                    plain_text = text_to_binary(word) + key_binary
                else:
                    plain_text = text_to_binary(word)

                cipher_text = self.__get_cipher_version(cipher, plain_text, self.block_cipher_size)
                for index in range(0, len(plain_text)):
                    text_version = self.__get_input_version(plain_text, index)
                    cipher_version = self.__get_cipher_version(cipher, text_version, self.block_cipher_size)
                    xored_cipheres = xor_two_bit_strings(cipher_text, cipher_version, self.block_cipher_size)
                    sac_matrix[index] = self._add_cipher_version_to_sac_matrix(sac_matrix[index], xored_cipheres)
                line_index = line_index + 1
        # plain_texts = self.__read_file_words()
        # cipher_texts = []
        # plain_texts_count = len(plain_texts)
        # for i in range(0, plain_texts_count):
        #     cipher_texts.append(self.__get_cipher_version(cipher, plain_texts[i], self.key))
        # sac_matrix = {i: [0] * self.block_cipher_size for i in range(self.block_cipher_size)}
        # for plain_text_index in range(0, plain_texts_count):
        #     plain_text = plain_texts[plain_text_index]
        #     print("the plain text index is: " + str(plain_text_index))
        #     for index in range(0, len(plain_text)):
        #         text_version = self.__get_input_version(plain_text, index)
        #         cipher_version = self.__get_cipher_version(cipher, text_version, self.block_cipher_size)
        #         xored_cipheres = xor_two_bit_strings(cipher_texts[plain_text_index], cipher_version, self.block_cipher_size)
        #         sac_matrix[index] = self._add_cipher_version_to_sac_matrix(sac_matrix[index], xored_cipheres)
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
        plt.plot(plot_keys, plot_values, label="نمودار فراوانی", color='blue', marker='o')
        plt.title("نمودار فراوانی داده‌ها", fontsize=16)
        plt.xlabel("کلیدها", fontsize=14)
        plt.ylabel("فراوانی", fontsize=14)
        # plt.xticks(np.arange(plot_keys.min(), plot_keys.max() + 1, step=5), fontsize=12)
        # plt.yticks(np.arange(plot_values.min(), plot_values.max() + 1, step=5), fontsize=12)
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.legend(fontsize=12)
        plt.tight_layout()
        plt.show()
        return sac_matrix, sd

    def __get_cipher_version(self, cipher, text, bits_count):
        if bits_count == 160:
            return cipher.encrypt(text, self.key, True)
        input_text = binary_to_hex(text)
        return hex_to_binary(cipher.feistel_function(input_text, self.key))

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

    def __read_file_words(self):
        words = []
        with open(self.file_path, 'r', encoding='ascii') as file:
            key_binary = hex_to_binary(self.key[0:12])
            for line in file:
                word = line.strip()
                if self.block_cipher_size != 160:
                    words.append(text_to_binary(word) + key_binary)
                else:
                    words.append(text_to_binary(word))
        return words
