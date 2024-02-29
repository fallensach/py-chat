import socket
import argparse
import pickle
import encrypted_communication
from Crypto.PublicKey import RSA
from client_frame import ClientFrame
from message_frame import MessageFrame

# Create a TCP socket
server_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

parser = argparse.ArgumentParser(description="A chat server socket")
parser.add_argument("--ip", "-i", type=str, help="Ip address of the server")
parser.add_argument("--port", "-p", type=int, help="Server port")

args = parser.parse_args()


def init_session(client_socket: socket.socket, client: ClientFrame, data: bytes, session_key: bytes):
    client.client_pub = RSA.import_key(data)
    client.enc_session_key = encrypted_communication.encrypt_key(session_key, client.client_pub)
    client_socket.sendall(client.enc_session_key)

def main():
    client = ClientFrame(None, None)
    session_key: bytes = encrypted_communication.generate_aes_key()
    if args.ip and not args.port:
        server_address = (str(args.ip), 4444)

    elif args.ip and args.port:
        server_address = (str(args.ip), args.port)
        
    else:
        server_address = ("localhost", 4444)

    
    server_socket.bind(server_address)
    # Listen for incoming connections
    server_socket.listen(5)
    print("Listening for connections ...")

        # Accept a connection
    client_socket, client_address = server_socket.accept()
    print("Connection accepted from:", client_address)
    try:
        init_session(client_socket, client, client_socket.recv(4096), session_key)
        while True:
            # Receive data from the client
            data = client_socket.recv(1024)
            
            if data: 
                message_frame: MessageFrame = pickle.loads(data)
                data = encrypted_communication.decrypt_data(message_frame, session_key, message_frame.tag, message_frame.nonce, client.client_pub)
                print(data.decode())
                client_socket.sendall(b'Recieved')

    except KeyboardInterrupt:
        server_socket.close()
    
if __name__ == "__main__":
    main()

