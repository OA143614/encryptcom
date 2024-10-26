import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os
import threading
import msvcrt
import sys

# Client settings
HOST = '127.0.0.1'
PORT = 65432

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Request public key from server
client.sendto(b"REQUEST_PUBLIC_KEY", (HOST, PORT))
try:
    public_pem, _ = client.recvfrom(8192)  # Increased buffer size
except ConnectionResetError as e:
    print(f"Connection error: {e}")
    exit()

# Load public key
public_key = serialization.load_pem_public_key(public_pem)

# Generate RC4 key
rc4_key = os.urandom(16)

# Encrypt RC4 key with server's public key
encrypted_key = public_key.encrypt(
    rc4_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Send encrypted RC4 key to server
client.sendto(b"KEY:" + encrypted_key, (HOST, PORT))
response, _ = client.recvfrom(1024)
print(response.decode())

# Define the cipher globally
cipher = Cipher(algorithms.ARC4(rc4_key), mode=None, backend=default_backend())

# Function to receive messages from the server
def receive_messages(client_socket):
    while True:
        try:
            encrypted_response, _ = client_socket.recvfrom(1024)
            decryptor = cipher.decryptor()
            response = decryptor.update(encrypted_response)
            print(f"Received response from server: {response.decode()}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Start the thread to handle incoming messages
thread = threading.Thread(target=receive_messages, args=(client,))
thread.start()

while True:
    sentence = ''
    while True:
        if msvcrt.kbhit():
            char = msvcrt.getwch()
            if char == '\r':  # Check for Enter key (carriage return)
                break
            sentence += char
            sys.stdout.write(char)
            sys.stdout.flush()
    if sentence:
        message = sentence.encode()
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message)

        # Send encrypted message to server
        client.sendto(encrypted_message, (HOST, PORT))

        sys.stdout.write(f"\n<You> {sentence}\n")
        sys.stdout.flush()

client.close()
