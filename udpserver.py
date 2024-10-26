import socket
import threading
from Cryptodome.Cipher import AES
import os

# Server settings
HOST = '127.0.0.1'
PORT = 65432

# Use a fixed AES key for simplicity
aes_key = b'This is a key123This is a key123'  # 32 bytes

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
    while True:
        message, addr = server.recvfrom(4096)
        if addr not in clients:
            clients.append(addr)
        # Decrypt message from client
        iv = message[:16]
        encrypted_message = message[16:]
        cipher = AES.new(aes_key, AES.MODE_CFB, iv)
        decrypted_message = cipher.decrypt(encrypted_message)
        print(f"Received message from {addr}: {decrypted_message.decode('utf-8', errors='ignore')}")
        
        # Encrypt message and send to clients
        iv = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_CFB, iv)
        encrypted_response = iv + cipher.encrypt(decrypted_message)
        broadcast(encrypted_response, addr)

# Start the thread to handle incoming messages
thread = threading.Thread(target=handle_messages)
thread.start()
