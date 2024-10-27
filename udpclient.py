import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Cipher import AES
import os

# Server settings
HOST = '127.0.0.1'
PORT = 65432

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.connect((HOST, PORT))

# Display connection info
print(f"Connected to server: {HOST}:{PORT}")

# Request public key from the server
client_socket.sendto(b"REQUEST_PUBLIC_KEY", (HOST, PORT))

# Receive the public key from the server
try:
    public_pem, addr = client_socket.recvfrom(2048)
    print(f"Received public key from {addr}")
    loaded_public_key = serialization.load_pem_public_key(public_pem)
except Exception as e:
    print(f"Failed to receive public key: {e}")

# Generate a valid AES key for encryption (32 bytes)
aes_key = b'\x92\x0f\xfa{\xe3u>H\xf9\x9e\x02\xc7T\xdd6\xec\xfc\x9d0\x18\xbf\x06\x9eu\x81\x90\xa1\x85T\xa6o\xf5'  # Generate a secure random 32-byte key

# Encrypt the AES key with the server's public key
encrypted_aes_key = loaded_public_key.encrypt(
    aes_key, 
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Send the encrypted AES key to the server
client_socket.sendto(b"KEY:" + encrypted_aes_key, (HOST, PORT))

# Function to receive messages from the server
def receive_messages(client_socket):
    while True:
        try:
            message, addr = client_socket.recvfrom(1024)
            if message:
                # Decrypt the message using the AES key
                iv = message[:16]
                encrypted_message = message[16:]
                cipher = AES.new(aes_key, AES.MODE_CFB, iv)
                decrypted_message = cipher.decrypt(encrypted_message)
                print(decrypted_message.decode('utf-8', errors='ignore'))
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Start a thread to receive messages
thread = threading.Thread(target=receive_messages, args=(client_socket,))
#thread.daemon = True
thread.start()

while True:
    try:
        sentence = input("")
        if sentence:
            iv = os.urandom(16)
            cipher = AES.new(aes_key, AES.MODE_CFB, iv)
            encrypted_message = iv + cipher.encrypt(sentence.encode('utf-8'))
            client_socket.sendto(encrypted_message, (HOST, PORT))
            print(f"You: {sentence}")
    except KeyboardInterrupt:
        print("\nConnection closed.")
        client_socket.close()
        break
