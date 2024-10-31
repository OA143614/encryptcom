import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Cipher import AES
import os

# Server settings
HOST = '127.0.0.1'
PORT = 65431

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

# Choose encryption method
encryption_method = input("Choose encryption method (unencrypted/AES): ")

# Flag to stop the receiving thread
stop_thread = threading.Event()

def receive_messages(client_socket):
    #print(client_socket)
    while not stop_thread.is_set():
        try:
            message, _ = client_socket.recvfrom(4096)
            if encryption_method == 'unencrypted':
                #print(message_choice)
                print(f"Server: {message.decode('utf-8', errors='ignore')}")
            elif encryption_method == 'AES':
                #print(message_choice)
                iv = message[:16]
                encrypted_message = message[16:]
                cipher = AES.new(aes_key, AES.MODE_CFB, iv)
                decrypted_message = cipher.decrypt(encrypted_message)
                print(decrypted_message.decode('utf-8', errors='ignore'))
        except Exception as e:
            if not stop_thread.is_set():
                print(f"Error receiving message: {e}")
            break



# Send the encryption method choice once
choice_method = encryption_method.encode('utf-8')
client.sendto(choice_method, (HOST, PORT))

try:
    while True:
        sentence = input("")
        if sentence:
            if encryption_method == 'unencrypted':
                message = sentence.encode('utf-8')
                client.sendto(message, (HOST, PORT))
            elif encryption_method == 'AES':
                iv = os.urandom(16)
                cipher = AES.new(aes_key, AES.MODE_CFB, iv)
                encrypted_message = iv + cipher.encrypt(sentence.encode('utf-8'))
                client.sendto(encrypted_message, (HOST, PORT))
            print(f"You: {sentence}")
        # Start a thread to receive messages
        thread = threading.Thread(target=receive_messages, args=(client,))
        thread.daemon = True
        thread.start()
except KeyboardInterrupt:
    print("\nConnection closed.")
finally:
    stop_thread.set()
    client.close()