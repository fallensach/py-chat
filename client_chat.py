import socket
import argparse
import encrypted_communication
import pickle

# Create a TCP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

parser = argparse.ArgumentParser(description="A chat server socket")
parser.add_argument("--ip", "-i", type=str, help="Ip address of the server")
parser.add_argument("--port", "-p", type=int, help="Server port")

args = parser.parse_args()


if args.ip and args.port:
    server_address = (str(args.ip), args.port)
else:
    raise ValueError("Ip or port not specified")

key_pair = encrypted_communication.generate_RSA_key()
pub_key = key_pair.public_key().export_key()
enc_session_key = None

client_socket.connect(server_address)

def receive_session_key(client_socket: socket.socket):
    enc_session_key = client_socket.recv(4096)
    return enc_session_key
 
try:
    client_socket.sendall(pub_key)
    enc_session_key = receive_session_key(client_socket)
    while True:
        message = input("Enter message: ").encode("utf-8")
        message_frame = encrypted_communication.encrypt_data(message, encrypted_communication.decrypt_key(enc_session_key, key_pair), key_pair)
        
        serialized_message_frame = pickle.dumps(message_frame)
        
        client_socket.sendall(serialized_message_frame)

        response = client_socket.recv(1024)
        if response:
            print("Received:", response.decode())
        
except KeyboardInterrupt:
    client_socket.close()
     

