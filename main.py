from Cipher.ProjectBlockCipher import ProjectBlockCipher
from Utilities.CipherUtilities import text_to_binary, binary_to_hex, binary_to_text, hex_to_binary

x = ProjectBlockCipher()
cipher_text = x.encrypt(text_to_binary("ahmadahmadahmadahmad"), text_to_binary("key1key1key1key1key1"), True)
plain_text = x.encrypt(cipher_text, text_to_binary("key1key1key1key1key1"), False)
print(cipher_text)
print(binary_to_text(cipher_text))
print("decrypted: "+ binary_to_text(plain_text))
