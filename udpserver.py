import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Cipher import DES3, AES
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
clients_lock = threading.Lock()

# Setting up the server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))
print(f"Server listening on {HOST}:{PORT}")

def broadcast(message, sender_addr):
    with clients_lock:
        for client in clients:
            if client != sender_addr:
                try:
                    server.sendto(message, client)
                except:
                    clients.remove(client)

def handle_messages(addr, cipher_type):
    key = None
    iv_size = 8 if cipher_type == '3DES' else 16  # Set iv_size based on cipher type
    while True:
        message, addr = server.recvfrom(4096)
        if message == b"REQUEST_PUBLIC_KEY":
            server.sendto(public_pem, addr)
        elif message.startswith(b"KEY:"):
            encrypted_key = message[4:]
            key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        else:
            with clients_lock:
                if addr not in clients:
                    clients.append(addr)
            iv, encrypted_message = None, None
            try:
                if cipher_type == '3DES':
                    iv = message[:8]
                    encrypted_message = message[8:]
                    cipher = DES3.new(key, DES3.MODE_CFB, iv)
                elif cipher_type == 'AES':
                    iv = message[:16]
                    encrypted_message = message[16:]
                    cipher = AES.new(key, AES.MODE_CFB, iv)
                else:
                    print("Unsupported cipher type")
                    continue

                decrypted_message = cipher.decrypt(encrypted_message)
                decoded_message = decrypted_message.decode('utf-8', errors='ignore')
                print(f"Received message from {addr}: {decoded_message}")

                # Encrypt message and send to clients
                iv = get_random_bytes(iv_size)
                cipher = DES3.new(key, DES3.MODE_CFB, iv) if cipher_type == '3DES' else AES.new(key, AES.MODE_CFB, iv)
                sender_info = f"{addr[0]}:{addr[1]}"
                full_message = f"{sender_info}: {decoded_message}"
                encrypted_response = iv + cipher.encrypt(full_message.encode('utf-8'))
                broadcast(encrypted_response, addr)
            except UnicodeDecodeError as e:
                print(f"Unicode decode error: {e}")
            except Exception as e:
                print(f"Error handling message: {e}")

def handle_client(addr, choice):
    if choice == 'unencrypted':
        while True:
            message, addr = server.recvfrom(4096)
            if message:
                try:
                    decoded_message = message.decode('utf-8', errors='ignore')
                    sender_info = f"{addr[0]}:{addr[1]}"
                    full_message = f"{sender_info}: {decoded_message}"
                    print(f"Message from unencrypt {sender_info} - {decoded_message}")
                    broadcast(full_message.encode('utf-8'), addr)
                except UnicodeDecodeError as e:
                    print(f"Unicode decode error: {e}")
    else:
        handle_messages(addr, choice)

while True:
    # Receive message from client
    message, addr = server.recvfrom(4096)
    try:
        decoded_message = message.decode('utf-8', errors='ignore')
        print(f"Received message: {decoded_message} from {addr}")

        # Send a response back to the client
        response = "Message received"
        server.sendto(response.encode(), addr)

        # Track connected clients
        with clients_lock:
            if addr not in clients:
                clients.append(addr)
        print(decoded_message)
        # Track client choices
        threading.Thread(target=handle_client, args=(addr, decoded_message)).start()

        print("Clients:", clients)
    except UnicodeDecodeError as e:
        print(f"Unicode decode error: {e}")
    except Exception as e:
        print(f"Error handling client message: {e}")