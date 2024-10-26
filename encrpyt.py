import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os

# Client settings
HOST = '127.0.0.1'
PORT = 65411

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Request public key from server
client.sendto(b"REQUEST_PUBLIC_KEY", (HOST, PORT))
public_pem, _ = client.recvfrom(4096)

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

# Encrypt a message using RC4
message = b"Hello from client!"
cipher = Cipher(algorithms.ARC4(rc4_key), mode=None, backend=default_backend())
encryptor = cipher.encryptor()
encrypted_message = encryptor.update(message)

# Send encrypted message to server
client.sendto(encrypted_message, (HOST, PORT))

# Receive and decrypt the response from the server
encrypted_response, _ = client.recvfrom(1024)
decryptor = cipher.decryptor()
response = decryptor.update(encrypted_response)
print(f"Received response from server: {response.decode()}")
