from Cipher.ProjectBlockCipher import ProjectBlockCipher
from Utilities.CipherUtilities import generate_iv, xor_two_bit_strings, text_to_binary


def ofb_mode(plain_texts, key):
    key = text_to_binary(key)
    iv = generate_iv(160)
    cipher = ProjectBlockCipher()
    input_text = iv
    cipher_text = ''
    for plain_text in plain_texts:
        temp = cipher.encrypt(input_text, key, True)
        cipher_text = cipher_text + xor_two_bit_strings(temp, text_to_binary(plain_text), 160)
        input_text = temp

    return cipher_text


plain_texts = ["yurUQp2gnwLvMdEVGJ5q",
               "LePfGA5xhjHUS2Vv4KMm",
               "Q82YEPZxJbSCrHDwqpWy",
               "eMk3nqTm96EzZKaNCfSh",
               "WPxG2Nv7RYhjQ4Dub8VS"]
print(ofb_mode(plain_texts, "12345678900987654321"))
