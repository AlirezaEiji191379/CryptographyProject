from Cipher.ProjectBlockCipher import ProjectBlockCipher
from Utilities.CipherUtilities import text_to_binary, binary_to_text

x = ProjectBlockCipher()
text = "ahmadahmadahmadahmad"
key = "1234567890abcdefghio"
text_binary = text_to_binary(text)
key_binary = text_to_binary(key)
cipher_text = x.encrypt(text_binary, key_binary, True)
print(binary_to_text(cipher_text))
plain_text_back = x.encrypt(cipher_text, key_binary, False)
print(binary_to_text(plain_text_back))