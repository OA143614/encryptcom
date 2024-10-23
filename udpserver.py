import socket
import threading
import rsa
import sys

# Generate public and private keys
publicKey, privateKey = rsa.newkeys(512)

# Save the public key to a file
with open('public_key.pem', 'w') as file:
    file.write(publicKey.save_pkcs1().decode())



# Server settings
HOST = '127.0.0.1'
PORT = 65432

# List to keep track of connected clients
clients = []

# Function to broadcast messages to all clients
def broadcast(message, sender_addr, sender_info):
    for client in clients:
        if client != sender_addr:
            try:
                full_message = f"{sender_info}: {message}"
                server.sendto(full_message.encode(), client)
            except:
                clients.remove(client)

# Setting up the server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))
print(f"Server listening on {HOST}:{PORT}")

# Function to handle incoming messages
def handle_messages():
    while True:
        message, addr = server.recvfrom(1024)
        try:
            decrypt_message = rsa.decrypt(message, privateKey).decode()
        except rsa.DecryptionError:
            print(f"Failed to decrypt message from {addr}")
            continue
        
        if addr not in clients:
            clients.append(addr)
        sender_info = f"{addr[0]}:{addr[1]}"
        print(f"Message from {sender_info} - {decrypt_message}")
        broadcast(decrypt_message, addr, sender_info)

# Start the thread to handle incoming messages
thread = threading.Thread(target=handle_messages)
thread.start()
