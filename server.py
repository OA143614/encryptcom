import socket
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Cipher import DES3, AES
from Cryptodome.Random import get_random_bytes
import os

# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize public key to send to client
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Server settings
HOST = '127.0.0.1'
PORT = 65431

clients = []
clients_choice = {}

# Send the message to another client
def broadcast(message, receiver_addr):
    try:
        server.sendto(message, receiver_addr)
        logging.info(f"Message sent to {receiver_addr}")
    except Exception as e:
        logging.error(f"Error sending message to {receiver_addr}: {e}")
        if receiver_addr in clients:
            clients.remove(receiver_addr)

# Broadcast to receiver's choice
def choice_message(decrypted_message, addr):
    logging.info(f"choice_message called with addr: {addr} and clients_choice: {clients_choice}")
    for client, choice in clients_choice.items():
        if client != addr:
            logging.info(f"Processing message for client: {client} with choice: {choice}")
            if choice == "unencrypted":
                decoded_message = decrypted_message.decode('utf-8', errors='ignore')
                sender_info = f"{addr[0]}:{addr[1]}"
                full_message = f"{sender_info}: {decoded_message}"
                print(f"Message from {sender_info} - {decoded_message}")
                broadcast(full_message.encode('utf-8'), client)
            elif choice == "AES":
                iv_aes = os.urandom(16)
                cipher = AES.new(aes_key, AES.MODE_CFB, iv_aes)
                sender_info = f"{addr[0]}:{addr[1]}"
                full_message = f"{sender_info}: {decrypted_message.decode('utf-8', errors='ignore')}"
                encrypted_response = iv_aes + cipher.encrypt(full_message.encode('utf-8'))
                logging.info(f"AES Encrypted response: {encrypted_response}")
                broadcast(encrypted_response, client)
            elif choice == "3DES":
                iv_des = os.urandom(8)
                cipher = DES3.new(des3_key, DES3.MODE_CFB, iv_des)
                sender_info = f"{addr[0]}:{addr[1]}"
                full_message = f"{sender_info}: {decrypted_message.decode('utf-8', errors='ignore')}"
                encrypted_response = iv_des + cipher.encrypt(full_message.encode('utf-8'))
                logging.info(f"DES3 Encrypted response: {encrypted_response}")
                broadcast(encrypted_response, client)

def sender_handle_client(addr, message):
    try:
        if addr in clients_choice:
            choice = clients_choice[addr]
            logging.info(f"Processing message for client: {addr} with choice: {choice}")
            if choice == "unencrypted":
                if isinstance(message, bytes):
                    decoded_message = message.decode('utf-8', errors='ignore')
                    print(f"Message from {addr} - {decoded_message}")
                    choice_message(decoded_message.encode('utf-8'), addr)
            elif choice == "AES":
                if isinstance(message, bytes):
                    iv_aes = message[:16]
                    encrypted_message = message[16:]
                    cipher = AES.new(aes_key, AES.MODE_CFB, iv_aes)
                    decrypted_message = cipher.decrypt(encrypted_message)
                    logging.info(f"Decrypted message from {addr}: {decrypted_message}")
                    choice_message(decrypted_message, addr)
            elif choice == "3DES":
                if isinstance(message, bytes):
                    iv_des = message[:8]
                    encrypted_message = message[8:]
                    cipher = DES3.new(des3_key, DES3.MODE_CFB, iv_des)
                    decrypted_message = cipher.decrypt(encrypted_message)
                    logging.info(f"Decrypted message from {addr}: {decrypted_message}")
                    choice_message(decrypted_message, addr)
    except UnicodeDecodeError as e:
        logging.error(f"Unicode decode error: {e}")
    except Exception as e:
        logging.error(f"Error handling client message: {e}")

while True:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((HOST, PORT))
    logging.info(f"Server listening on {HOST}:{PORT}")
    try:
        message, addr = server.recvfrom(4096)
        logging.info(f"Received message from {addr}")
        
        if isinstance(message, bytes):
            receive_message = message.decode('utf-8', errors='ignore')
        else:
            receive_message = message

        if receive_message == 'connect' and addr not in clients:
            clients.append(addr)
            server.sendto(public_pem, addr)
            logging.info(f"Sent public key to {addr}")

            # Receive AES key
            message, addr = server.recvfrom(4096)
            encrypted_key = message
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logging.info(f"Received and decrypted AES key from {addr}")

            # Receive 3DES key
            message, addr = server.recvfrom(4096)
            encrypted_key = message
            des3_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logging.info(f"Received and decrypted 3DES key from {addr}")
            logging.info(f"New client added: {addr}")
            print(clients)

        elif receive_message in ['unencrypted', 'AES', '3DES']:
            clients_choice[addr] = receive_message
            logging.info(f"Client {addr} chose {receive_message} encryption")
            print(clients_choice)

        else:
            sender_handle_client(addr, message)

    except KeyboardInterrupt:
        logging.info("Server is shutting down due to keyboard interrupt.")
        break
    except Exception as e:
        logging.error(f"Error receiving message: {e}")
        