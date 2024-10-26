import socket
import threading
from Cryptodome.Cipher import AES
import os

# Server settings
HOST = '127.0.0.1'
PORT = 65432

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.connect((HOST, PORT))

# Display connection info
print(f"Connected to server: {HOST}:{PORT}")

# Use the same fixed AES key as the server
aes_key = b'This is a key123This is a key123'  # 32 bytes

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
                print(f"Server: {decrypted_message.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Start a thread to receive messages
thread = threading.Thread(target=receive_messages, args=(client_socket,))
thread.daemon = True
thread.start()

while True:
    try:
        sentence = input("Enter message to send: ")
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
