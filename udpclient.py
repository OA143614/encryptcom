import socket
import threading
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Cipher import DES3, AES
from Cryptodome.Random import get_random_bytes
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Server settings
HOST = str(sys.argv[1]) #= '127.0.0.1'
PORT = int(sys.argv[2])   #65431

# Create a UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Request public key from the server
client.sendto(b"REQUEST_PUBLIC_KEY", (HOST, PORT))
public_pem, addr = client.recvfrom(2048)
loaded_public_key = serialization.load_pem_public_key(public_pem)

#send AES key to server encryp with public key
aes_key = b'\x92\x0f\xfa{\xe3u>H\xf9\x9e\x02\xc7T\xdd6\xec\xfc\x9d0\x18\xbf\x06\x9eu\x81\x90\xa1\x85T\xa6o\xf5'
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
client.sendto(encrypted_aes_key, (HOST, PORT))

# Generate a valid 3DES key for encryption (24 bytes)
des3_key = b'\x7fk\x80\x8f\xba\xbc\xcbL\x97\x9b\xa7\xe9R\x0e\x0b\xdc\ry\xf7\xd3u\xfe*\xf8'

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
client.sendto(encrypted_des3_key, (HOST, PORT))

# Flag to stop the receiving thread
stop_thread = threading.Event()

#for recieve message from server
def receive_messages(client_socket,encryption_method,debug_option):
    if debug_option == 'on':
        logging.info(f"Client Socket: {client_socket}")

    #print(client_socket)
    while True:
        if debug_option == 'on':
            logging.info("Listening for messages...")
        try:
            message, _ = client_socket.recvfrom(4096)
            if debug_option == 'on':
                logging.info(f"Raw message received: {message}")
            if encryption_method == 'unencrypted':
                print(message.decode('utf-8', errors='ignore'))
            elif encryption_method == 'AES':
                iv_aes = message[:16]
                encrypted_message = message[16:]
                cipher = AES.new(aes_key, AES.MODE_CFB, iv_aes)
                decrypted_message = cipher.decrypt(encrypted_message)
                print(decrypted_message.decode('utf-8', errors='ignore'))
            elif encryption_method == '3DES':
                iv_des = message[:8]
                encrypted_message = message[8:]
                cipher = DES3.new(des3_key, DES3.MODE_CFB, iv_des)
                decrypted_message = cipher.decrypt(encrypted_message)
                print(decrypted_message.decode('utf-8', errors='ignore'))
            
        except Exception as e:
            if not stop_thread.is_set():
                print(f"Error receiving message: {e}")
            break

def send_message(encryption_method,debug_option):
    if debug_option == 'on':
        logging.info(f"Starting send_message with encryption method: {encryption_method}")
    encryption_method = encryption_method
    # Start a thread to receive messages
    thread = threading.Thread(target=receive_messages, args=(client,encryption_method,debug_option))
    thread.daemon = True
    thread.start()
    try:

        while True:
            sentence = input("")
            if sentence:
                if debug_option == 'on':
                    logging.info(f"Message to send: {sentence}")
                if encryption_method == 'unencrypted':
                    message = sentence.encode('utf-8')
                    client.sendto(message, (HOST, PORT))
                    if debug_option == 'on':
                        logging.info("Sent unencrypted message")
                elif encryption_method == 'AES':
                    iv_aes = os.urandom(16)
                    cipher = AES.new(aes_key, AES.MODE_CFB, iv_aes)
                    encrypted_message = iv_aes + cipher.encrypt(sentence.encode('utf-8'))
                    client.sendto(encrypted_message, (HOST, PORT))
                    if debug_option == 'on':
                        logging.info("Sent AES encrypted message")
                elif encryption_method == '3DES':
                    iv_des = get_random_bytes(8)
                    cipher = DES3.new(des3_key, DES3.MODE_CFB, iv_des)
                    encrypted_message = iv_des + cipher.encrypt(sentence.encode('utf-8'))
                    client.sendto(encrypted_message, (HOST, PORT))
                    if debug_option == 'on':
                        logging.info("Sent 3DES encrypted message")
                print(f"You: {sentence}")
            
            
    except KeyboardInterrupt:
        print("\nConnection closed.")
    finally:
        stop_thread.set()
        client.close()

def send_option(option):
    
    client.sendto(option.encode(), (HOST, PORT))

def user_interaction():
    while True:
        choose_option = input("Please select an option:\n1. Help\n2. Debug and Mode\n")
        if choose_option == '1':
            print("press 2 to choose debug mode press on for displaying log press off for not display log. \nThen press u for unencrypt, press a1 for AES encryption, and press a2 for 3DES encryption.")
            user_interaction()
        elif choose_option == '2':
            while True:
                #encryption_method = None  # Initialize the variable
                debug_option = input("Please choose on/off log:\nType 'on' for on log\nType 'off' for off log:\n")
                if debug_option in ['on', 'off']:
                   
                    chose_encryption_method = input("Choose encryption method (u/a1/a2): ")
                    if chose_encryption_method == 'u':
                        encryption_method = 'unencrypted'
                        # Send the encryption method choice once
                        send_option(encryption_method)
                        send_message(encryption_method,debug_option)
                    elif chose_encryption_method == 'a1':
                        encryption_method = 'AES'
                        # Send the encryption method choice once
                        send_option(encryption_method)
                        send_message(encryption_method,debug_option)
                    elif chose_encryption_method == 'a2':
                        encryption_method = '3DES'
                        # Send the encryption method choice once
                        send_option(encryption_method)
                        send_message(encryption_method,debug_option)
                    else:
                        print("Invalid option. Please try again.") 
                        continue
                    
                    
                    break
                break
            else:
                print("Invalid option. Please try again.")             
        else:
            print("Invalid option. Please try again.")




user_interaction()











