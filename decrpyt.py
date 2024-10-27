import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Cipher import DES3
from Cryptodome.Random import get_random_bytes
import os

# Server settings
HOST = '127.0.0.1'
PORT = 65432

# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize public key to send to client
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)



# List to keep track of connected clients
clients = []

# Setting up the server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))
print(f"Server listening on {HOST}:{PORT}")

def broadcast(message, sender_addr):
    for client in clients:
        if client != sender_addr:
            try:
                server.sendto(message, client)
            except:
                clients.remove(client)

def handle_messages():
    global des3_key
    while True:
        message, addr = server.recvfrom(4096)
        if message == b"REQUEST_PUBLIC_KEY":
            server.sendto(public_pem, addr)
        elif message.startswith(b"KEY:"):
            encrypted_key = message[4:]
            des3_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            """ print(f"Received 3DES key: {des3_key}")
            response = b"3DES key received!"
            server.sendto(response, addr) """
        else:
            if addr not in clients:
                clients.append(addr)
            # Decrypt message from client
            iv = message[:8]
            encrypted_message = message[8:]
            cipher = DES3.new(des3_key, DES3.MODE_CFB, iv)
            decrypted_message = cipher.decrypt(encrypted_message)
            print(f"Received message from {addr}: {decrypted_message.decode('utf-8', errors='ignore')}")
            
            # Encrypt message and send to clients
            iv = get_random_bytes(8)
            cipher = DES3.new(des3_key, DES3.MODE_CFB, iv)
            sender_info = f"{addr[0]}:{addr[1]}"
            full_message = f"{sender_info}: {decrypted_message.decode('utf-8', errors='ignore')}"
            encrypted_response = iv + cipher.encrypt(full_message.encode('utf-8'))
            #encrypted_response = iv + cipher.encrypt(decrypted_message)
            broadcast(encrypted_response, addr)

# Start the thread to handle incoming messages
thread = threading.Thread(target=handle_messages)
thread.start()
