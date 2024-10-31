import socket
import threading
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Cipher import DES3, AES
from Cryptodome.Random import get_random_bytes
import os

# Server settings
HOST = '127.0.0.1'
PORT = 65431

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
clients_choice =[]

# Setting up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Setting up the server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))
logging.info(f"Server listening on {HOST}:{PORT}")



#broad

def broadcast(message, sender_addr):
    with clients_lock:
        for client in clients:
            if client != sender_addr:
                try:
                    server.sendto(message, client)
                    logging.info(f"Message sent to {client}")
                except Exception as e:
                    logging.error(f"Error sending message to {client}: {e}")
                    clients.remove(client)

def handle_client(addr,choice_decoded_message,client_choice):
   
    while True:
        if len(clients) == 2:
            try:
                message, addr = server.recvfrom(4096)
                if choice_decoded_message == "unencrypted":
                    if message:
                        decoded_message = message.decode('utf-8', errors='ignore')
                        sender_info = f"{addr[0]}:{addr[1]}"
                        full_message = f"{sender_info}: {decoded_message}"
                        print(f"Message from {sender_info} - {decoded_message}")
                        broadcast(full_message.encode('utf-8'), addr)
                elif choice_decoded_message == "AES": 
                    if message:
                        iv = message[:16]
                        encrypted_message = message[16:]
                        cipher = AES.new(aes_key, AES.MODE_CFB, iv)
                        decrypted_message = cipher.decrypt(encrypted_message)
                        print(f"Received message from {addr}: {decrypted_message.decode('utf-8', errors='ignore')}")
                    with clients_lock:
                        for client in clients:
                            if client != addr:
                                if client_choice[1][1] == "unencrypted":
                                    decoded_message = decrypted_message.decode('utf-8', errors='ignore')
                                    sender_info = f"{addr[0]}:{addr[1]}"
                                    full_message = f"{sender_info}: {decoded_message}"
                                    print(f"Message from {sender_info} - {decoded_message}")
                                    broadcast(full_message.encode('utf-8'), addr)
                                elif client_choice[1][1] == "AES":
                                    # Encrypt message and send to clients
                                    iv = os.urandom(16)
                                    cipher = AES.new(aes_key, AES.MODE_CFB, iv)
                                    sender_info = f"{addr[0]}:{addr[1]}"
                                    full_message = f"{sender_info}: {decrypted_message.decode('utf-8', errors='ignore')}"
                                    encrypted_response = iv + cipher.encrypt(full_message.encode('utf-8'))
                                    broadcast(encrypted_response, addr)

                        
      
            except UnicodeDecodeError as e:
                logging.error(f"Unicode decode error: {e}")
            except Exception as e:
                logging.error(f"Error handling client message: {e}")
                with clients_lock:
                    if addr in clients:
                        clients.remove(addr)
                break

def main():
    global aes_key
    while True:
        with clients_lock:
            #Handle 2 clients
            if len(clients) < 2:
                #send public key to client
                message, addr = server.recvfrom(4096)
                server.sendto(public_pem, addr)

                #receive AES key
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
                print(aes_key)
                # Receive message from client
                message, addr = server.recvfrom(4096)
                choice_decoded_message = message.decode('utf-8', errors='ignore')
                print(f"Received message: {choice_decoded_message} from {addr}")
                
                if addr not in clients:
                    clients.append(addr)
                    clients_choice.append((addr,choice_decoded_message))
            
            #start threading
            threading.Thread(target=handle_client, args=(addr,choice_decoded_message,clients_choice)).start()
        
if __name__ == "__main__":
    main()
