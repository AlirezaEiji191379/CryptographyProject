import hashlib

import numpy as np

from Cipher.ProjectBlockCipher import ProjectBlockCipher
from Utilities.CipherUtilities import xor_two_hex_strings

x = ProjectBlockCipher()

round_binary = bin(5)[2:]
input_key = round_binary + "123456789"
sha256_key = hashlib.sha256(input_key.encode()).hexdigest()
print(sha256_key)
print(len(sha256_key))
