import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize public key to send to client
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Server settings
HOST = '127.0.0.1'
PORT = 65432

# List to keep track of connected clients
clients = []

# Setting up the server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))
print(f"Server listening on {HOST}:{PORT}")

rc4_key = None

def broadcast(message, sender_addr, sender_info):
    for client in clients:
        if client != sender_addr:
            try:
                full_message = f"{sender_info}: {message.decode()}"
                server.sendto(full_message.encode(), client)
            except:
                clients.remove(client)

def handle_messages():
    global rc4_key
    while True:
        message, addr = server.recvfrom(4096)
        if message == b"REQUEST_PUBLIC_KEY":
            server.sendto(public_pem, addr)
        elif message.startswith(b"KEY:"):
            encrypted_key = message[4:]
            rc4_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Received RC4 key: {rc4_key}")
            response = b"RC4 key received!"
            server.sendto(response, addr)
        else:
            if rc4_key:
                if addr not in clients:
                    clients.append(addr)
                # Decrypt message from client
                cipher = Cipher(algorithms.ARC4(rc4_key), mode=None, backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_message = decryptor.update(message)
                print(f"Received message from {addr}: {decrypted_message.decode()}")
                
                # Encrypt message and send to clients
                sender_info = f"{addr[0]}:{addr[1]}"
                response = b"Hello from server!"
                encryptor = cipher.encryptor()
                encrypted_response = encryptor.update(response)
                broadcast(encrypted_response, addr, sender_info)

# Start the thread to handle incoming messages
thread = threading.Thread(target=handle_messages)
thread.start()
