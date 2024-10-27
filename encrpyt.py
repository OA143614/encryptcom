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

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.connect((HOST, PORT))

# Display connection info
print(f"Connected to server: {HOST}:{PORT}")

# Request public key from the server
client_socket.sendto(b"REQUEST_PUBLIC_KEY", (HOST, PORT))

# Receive the public key from the server
try:
    public_pem, addr = client_socket.recvfrom(2048)
    #print(f"Received public key from {addr}")
    loaded_public_key = serialization.load_pem_public_key(public_pem)
except Exception as e:
    print(f"Failed to receive public key: {e}")

# Generate a valid 3DES key for encryption (24 bytes)
des3_key = b'\x7fk\x80\x8f\xba\xbc\xcbL\x97\x9b\xa7\xe9R\x0e\x0b\xdc\ry\xf7\xd3u\xfe*\xf8'
#print(des3_key)
# Encrypt the 3DES key with the server's public key
encrypted_des3_key = loaded_public_key.encrypt(
    des3_key, 
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Send the encrypted 3DES key to the server
client_socket.sendto(b"KEY:" + encrypted_des3_key, (HOST, PORT))

# Function to receive messages from the server
def receive_messages(client_socket):
    while True:
        try:
            message, addr = client_socket.recvfrom(1024)
            if message:
                # Decrypt the message using the 3DES key
                iv = message[:8]
                encrypted_message = message[8:]
                cipher = DES3.new(des3_key, DES3.MODE_CFB, iv)
                decrypted_message = cipher.decrypt(encrypted_message)
                print(decrypted_message.decode('utf-8', errors='ignore'))
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Start a thread to receive messages
thread = threading.Thread(target=receive_messages, args=(client_socket,))
thread.daemon = True
thread.start()

while True:
    try:
        sentence = input("")
        if sentence:
            iv = get_random_bytes(8)
            cipher = DES3.new(des3_key, DES3.MODE_CFB, iv)
            encrypted_message = iv + cipher.encrypt(sentence.encode('utf-8'))
            client_socket.sendto(encrypted_message, (HOST, PORT))
            print(f"You: {sentence}")
    except KeyboardInterrupt:
        print("\nConnection closed.")
        client_socket.close()
        break
