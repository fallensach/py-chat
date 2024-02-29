class ClientFrame:
    def __init__(self, client_pub, enc_session_key) -> None:
        self.client_pub = client_pub
        self.enc_session_key = enc_session_key
    
    def __str__(self) -> str:
        return f'Client public key:\n {self.client_pub} \n Session_key:\n{self.enc_session_key}'