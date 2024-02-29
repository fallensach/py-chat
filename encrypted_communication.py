from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from message_frame import MessageFrame

def generate_RSA_key() -> RSA.RsaKey:
    """ Generate a RSA keypair with keylength 2048-bits
    """
    return RSA.generate(2048)

def generate_aes_key() -> bytes:
    """ Generate an AES key of length 16-bytes

    Returns:
        bytes: AES key
    """
    key = get_random_bytes(16)
    return key 

def verify_signature(message_frame: MessageFrame, pub_key: RSA.RsaKey, hash: SHA256.SHA256Hash) -> bool:
    """ Verifies that the message frame has not been tampered with.

    Args:
        message_frame (MessageSec): Frame containing encrypted data and it's signature 
        pub_key (RSA.RsaKey): Public key of the sender

    Returns:
        bool: True if signature matches
    """
    try: 
        pkcs1_15.new(pub_key).verify(hash, message_frame.signature)
        return True
    except:
        return False
    
def sign_hash(hash: SHA256.SHA256Hash, priv_key: RSA.RsaKey) -> bytes:
    """ Sign a given hash with the private key.

    Args:
        hash (SHA256.SHA256Hash): Hash to be signed
        priv_key (RSA.RsaKey): Key to sign with

    Returns:
        SHA265Hash: Signed hash object 
    """
    enc_hash = pkcs1_15.new(priv_key).sign(hash)
    return enc_hash

def encrypt_key(key: bytes, pub_key: RSA.RsaKey) -> bytes:
    """ Encrypt a given key with RSA.

    Args:
        key (bytes): Secret key to encrypt
        pub_key (RSA.RsaKey): Receiver's public key

    Returns:
        bytes: Key encrypted with RSA
    """
    rsa = PKCS1_OAEP.new(pub_key)
    return rsa.encrypt(key)

def decrypt_key(enc_key: bytes, priv_key: RSA.RsaKey) -> bytes:
    """ Decrypt an encrypted key with RSA.

    Args:
        enc_key (bytes): Key to decrypt 
        priv_key (RSA.RsaKey): Private key of the receiver 

    Returns:
        bytes: Decrypted key
    """
    rsa = PKCS1_OAEP.new(priv_key)
    return rsa.decrypt(enc_key)
    
def encrypt_data(data: bytes, session_key: bytes, priv_key: RSA.RsaKey) -> MessageFrame: 
    """ Encrypts and signs the data into a MessageFrame.

    Args:
        data (bytes): Data to be encrypted 
        session_key (bytes): AES Key 
        priv_key (RSA.RsaKey): Private key of the sender 

    Returns:
        MessageFrame: MessageFrame containing signed data. Also Tag and Nonce from the AES cipher. 
    """
    aes_cipher = AES.new(session_key, AES.MODE_EAX)
    cipher_text, tag = aes_cipher.encrypt_and_digest(data)
    nonce = aes_cipher.nonce
    hash = SHA256.new(data)
    signature = sign_hash(hash, priv_key)
    cipher_frame = MessageFrame(cipher_text, signature, tag, nonce)
    return cipher_frame

def decrypt_data(cipher_frame: MessageFrame, session_key: bytes, tag: bytes, nonce: bytes, pub_key: RSA.RsaKey) -> bytes:
    """ Decrypt and verify a given MessageFrame.

    Args:
        cipher_frame (MessageSec):  
        session_key (bytes): Message frame with encrypted cipher data 
        tag (bytes): Tag from sending AES cipher 
        nonce (bytes): Nonce from sending AES cipher
        pub_key (RSA.RsaKey): Public key of sender 

    Raises:
        ValueError: Fails if signature has been tampered with 

    Returns:
        bytes: The original message from the sender 
    """
    aes_cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce) 
    data = aes_cipher.decrypt_and_verify(cipher_frame.message, tag)
    hash = SHA256.new(data)
    
    if not verify_signature(cipher_frame, pub_key, hash):
       raise ValueError("Aborting session. Signature is corrupted or has been tampered with.")

    return data
    

def main():
    user_1: RSA.RsaKey = generate_RSA_key()
    user_2: RSA.RsaKey = generate_RSA_key()
    session_key = generate_aes_key()
    message_frame = encrypt_data(b'This is a secret message!', session_key, user_1)
    enc_session_key = encrypt_key(session_key, user_2.public_key())
    dec_session_key = decrypt_key(enc_session_key, user_2)
     
    message = decrypt_data(message_frame, dec_session_key, message_frame.tag, message_frame.nonce, user_1.public_key())
    print(message.decode("utf-8"))
    
if __name__ == "__main__":
    main()