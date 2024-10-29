import socket
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Cipher import DES3, AES
from Cryptodome.Random import get_random_bytes
import os

# Server settings
HOST = '127.0.0.1'
PORT = 65432

# Load the server's public key
def load_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)

# Encrypt the session key with the server's public key
def encrypt_session_key(public_key, session_key):
    return public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Create a UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Request the server's public key
client.sendto(b"REQUEST_PUBLIC_KEY", (HOST, PORT))
public_pem, _ = client.recvfrom(4096)
public_key = load_public_key(public_pem)


# Choose encryption method
encryption_method = input("Choose encryption method (unencrypted/3DES/AES): ")

session_key = None
iv_size = 0

if encryption_method == '3DES':
    session_key = b'\x7fk\x80\x8f\xba\xbc\xcbL\x97\x9b\xa7\xe9R\x0e\x0b\xdc\ry\xf7\xd3u\xfe*\xf8'  # 3DES key size
    iv_size = 8
elif encryption_method == 'AES':
    session_key = b'\x92\x0f\xfa{\xe3u>H\xf9\x9e\x02\xc7T\xdd6\xec\xfc\x9d0\x18\xbf\x06\x9eu\x81\x90\xa1\x85T\xa6o\xf5'  # AES key size
    iv_size = 16
elif encryption_method == 'unencrypted':
    iv_size = 0
else:
    print("Invalid encryption method chosen.")
    exit()

if session_key:
    encrypted_session_key = encrypt_session_key(public_key, session_key)
    client.sendto(b"KEY:" + encrypted_session_key, (HOST, PORT))

def receive_messages(client_socket):
    while True:
        try:
            message, _ = client_socket.recvfrom(4096)
            if encryption_method == 'unencrypted':
                print(f"Server: {message.decode('utf-8', errors='ignore')}")
            else:
                iv = message[:iv_size]
                encrypted_message = message[iv_size:]
                if encryption_method == '3DES':
                    cipher = DES3.new(session_key, DES3.MODE_CFB, iv)
                elif encryption_method == 'AES':
                    cipher = AES.new(session_key, AES.MODE_CFB, iv)
                decrypted_message = cipher.decrypt(encrypted_message)
                print(f"Server: {decrypted_message.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"Error receiving message: {e}")

# Start a thread to receive messages
thread = threading.Thread(target=receive_messages, args=(client,))
thread.daemon = True
thread.start()

while True:
    try:
        sentence = input("Enter message: ")
        if sentence:
            iv = get_random_bytes(iv_size)
            if encryption_method == '3DES':
                cipher = DES3.new(session_key, DES3.MODE_CFB, iv)
                encrypted_message = iv + cipher.encrypt(sentence.encode('utf-8'))
                client.sendto(encrypted_message, (HOST, PORT))
            elif encryption_method == 'AES':
                cipher = AES.new(session_key, AES.MODE_CFB, iv)
                encrypted_message = iv + cipher.encrypt(sentence.encode('utf-8'))
                client.sendto(encrypted_message, (HOST, PORT))
            elif encryption_method == 'unencrypted':
                message = sentence.encode('utf-8')
                client.sendto(message, (HOST, PORT))
            print(f"You: {sentence}")
    except KeyboardInterrupt:
        print("\nConnection closed.")
        client.close()
        break