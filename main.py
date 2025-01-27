from Cipher.ProjectBlockCipher import ProjectBlockCipher
from Utilities.CipherUtilities import text_to_binary, binary_to_hex, binary_to_text, hex_to_binary

x = ProjectBlockCipher()
# # print(text_to_binary("ahmadahmadahmadahmad"))
# # print(text_to_binary("key1key1key1key1key1"))
# cipher_text = x.encrypt(text_to_binary("ahmadahmadahmadahmad"), text_to_binary("key1key1key1key1key1"), True)
# plain_text = x.encrypt(cipher_text, text_to_binary("key1key1key1key1key1"), False)
# print(cipher_text)
# print(binary_to_text(cipher_text))
# print("decrypted: "+ binary_to_text(plain_text))
is_enc = True
plain_text_path = "./plain_text.txt"
cipher_text_path = "./result_cipher.txt"
if not is_enc:
    plain_text_path = "./result_cipher.txt"
    cipher_text_path = "./plain_text.txt"
with open("./key.txt", 'r', encoding='ascii') as file:
    key = file.read()
with open(plain_text_path, 'r', encoding='ascii') as text_file:
    plain_text = text_file.read()

cipher_text = x.encrypt(plain_text, key, is_enc)
decrypted = x.encrypt(cipher_text, key, False)
print(binary_to_text(cipher_text))
print(binary_to_text(decrypted))
with open(cipher_text_path, 'w', encoding='ascii') as cipher_text_file:
    cipher_text_file.write(cipher_text)

