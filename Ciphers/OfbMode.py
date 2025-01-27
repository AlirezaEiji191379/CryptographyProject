from Ciphers.ProjectBlockCipher import ProjectBlockCipher
from Utilities.CipherUtilities import generate_iv, xor_two_bit_strings, text_to_binary


def ofb_mode(plain_texts, key):
    key = text_to_binary(key)
    iv = generate_iv(160)
    cipher = ProjectBlockCipher(9, 8)
    input_text = iv
    cipher_text = ''
    for plain_text in plain_texts:
        temp = cipher.encrypt(input_text, key, True)
        cipher_text = cipher_text + xor_two_bit_strings(temp, text_to_binary(plain_text), 160)
        input_text = temp

    return cipher_text

def ofb_mode2(key):
    key = text_to_binary(key)
    iv = generate_iv(160)
    cipher = ProjectBlockCipher(9, 8)
    input_text = iv
    for i in range(0, 1000):
        print(i)
        temp = cipher.encrypt(input_text, key, True)
        with open("ofb_text.txt", "a") as file:
            file.write(temp)
        input_text = temp

ofb_mode2("12345678900987654321")
# plain_texts = ["Uhc28WAdBn6tRe4r7uTV",
#                "s2v74TSQadcpK6YX8Reg",
#                "Q82YEPZxJbSCrHDwqpWy",
#                "eMk3nqTm96EzZKaNCfSh",
#                "WPxG2Nv7RYhjQ4Dub8VS",
#                "q2WcXHz4FAxCULevEmKB",
#                "DkJuANyrZ2Vs4Ccbx6HW",
#                "dc8ya9GwbjDLe3gQNU4k",
#                "vGthKJCsAnVP4Tu3jZcy",
#                "y_lAtKj:8H[Z7$NLsS*E"]
# print(ofb_mode(plain_texts, "12345678900987654321"))
