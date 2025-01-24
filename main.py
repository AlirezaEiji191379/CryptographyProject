from Cipher.ProjectBlockCipher import ProjectBlockCipher
from Utilities.CipherUtilities import text_to_binary

x = ProjectBlockCipher()
cipher_text= x.encrypt(text_to_binary("alirezaeijialirezaei"), text_to_binary("12345678900987654321"), True)
plain_text = x.encrypt(cipher_text, text_to_binary("12345678900987654321"), False)
print(cipher_text)
