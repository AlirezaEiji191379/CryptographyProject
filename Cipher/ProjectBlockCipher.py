from Cipher.Exceptions.InvalidLengthException import InvalidLengthException


class ProjectBlockCipher:
    def __init__(self):
        pass

    def encrypt(self, plain_text : str, key : str) -> str:
        self.__validate_inputs(plain_text, key)
        pass

    def decrypt(self, cipher_text : str, key : str) -> str:
        self.__validate_inputs(cipher_text, key)
        pass

    def __validate_inputs(self, text: str, key : str):
        if len(text) > 160:
            raise InvalidLengthException("The length of the text must be less than 160 characters.")

        if len(key) > 160:
            raise InvalidLengthException("The length of the key must be less than 160 characters.")




    def __substitution(self, nibble : str):
        pass

    def __mix_column(self):
        pass

    def __shift_rows(self):
        pass

    def __add_gf(self, keybits : str):
        pass

    def __feistel_function_rounds(self):
        pass

