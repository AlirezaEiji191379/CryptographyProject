class BlockCipherService:
    def __init__(self):
        pass

    def __pad_input(self, text : str) -> str:
        if len(text) < 160:
            return text.zfill(160)
        return text