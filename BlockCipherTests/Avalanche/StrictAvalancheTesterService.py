from Cipher.ProjectBlockCipher import ProjectBlockCipher
from Cipher.Exceptions.InvalidLengthException import InvalidLengthException
from Utilities.CipherUtilities import xor_two_bit_strings
import matplotlib.pyplot as plt
import numpy as np


class StrictAvalancheTesterService:
    def __init__(self, plain_texts_file_path, key):
        self.file_path = plain_texts_file_path
        self.key = ''.join(format(ord(char), '08b') for char in key)

    def do_sac_test(self):
        cipher = ProjectBlockCipher()
        plain_texts = self.__read_file_words()
        cipher_texts = []
        plain_texts_count = len(plain_texts)
        for i in range(0, plain_texts_count):
            cipher_texts.append(cipher.encrypt(plain_texts[i], self.key))
        sac_matrix = {i: [0] * 160 for i in range(160)}
        for plain_text in plain_texts:
            binary_text = ''.join(format(ord(char), '08b') for char in plain_text)
            for index in range(0, len(binary_text)):
                text_version = self.__get_input_version(binary_text, index)
                cipher_version = cipher.encrypt(text_version, self.key)
                xored_cipheres = xor_two_bit_strings(cipher_texts[index], cipher_version, 160)
                sac_matrix[index] = self._add_cipher_version_to_sac_matrix(sac_matrix[index], xored_cipheres)
        abundance = {}
        for list_value in sac_matrix.values():
            for value in list_value:
                if value not in abundance:
                    abundance[value] = 1
                else:
                    abundance[value] = abundance[value] + 1

        keys = list(abundance.keys())
        values = list(abundance.values())
        x = np.linspace(min(keys), max(keys), 500)
        y = np.interp(x, keys, values)
        plt.figure(figsize=(8, 5))
        plt.plot(x, y, label="نمودار فراوانی", color='blue')
        plt.scatter(keys, values, color='red', label="داده‌های معیار بهمنی")
        plt.title("نمودار فراوانی")
        plt.legend()
        plt.grid(True)
        plt.show()


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
            for line in file:
                word = line.strip()
                if len(word) != 20:
                    raise InvalidLengthException("invalid plain text length")
                words.append(word)
        return words

x = StrictAvalancheTesterService("./plaintexts.txt", "123")
x.do_sac_test()