from Crypto.Hash import SHA256
class MessageFrame:
    """ Data frame for secure messages.
    """
    def __init__(self, message: bytes, signature: bytes, tag: bytes, nonce: bytes) -> None:
        self.message: bytes = message
        self.signature: bytes = signature
        self.tag: bytes = tag
        self.nonce: bytes = nonce
     
    def __str__(self) -> str:
        return f'Message frames'