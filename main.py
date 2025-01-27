from Cipher.ProjectBlockCipher import ProjectBlockCipher
from Utilities.CipherUtilities import text_to_binary, binary_to_hex, binary_to_text, hex_to_binary
import argparse

parser = argparse.ArgumentParser(description="Example script with boolean argument.")
parser.add_argument('--enc', type=str, choices=['true', 'false'], required=True,
                    help="Set to 'true' or 'false' to specify encryption status.")

args = parser.parse_args()
is_enc = args.enc.lower() == 'true'
x = ProjectBlockCipher()
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
print(binary_to_text(cipher_text))
with open(cipher_text_path, 'w', encoding='ascii') as cipher_text_file:
    cipher_text_file.write(cipher_text)

