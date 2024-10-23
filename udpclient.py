import socket
import threading
import msvcrt
import sys
import rsa

# Read the public key from the file
with open('public_key.pem', 'r') as file:
    publicKeyStr = file.read()

# Load the public key from the serialized string
loaded_publicKey = rsa.PublicKey.load_pkcs1(publicKeyStr.encode())


# Server settings
HOST = '127.0.0.1'
PORT = 65432

# Function to receive messages from the server
def receive_messages(client_socket):
    while True:
        try:
            message, addr = client_socket.recvfrom(1024)
            if message:
                print(message.decode())
        except:
            break

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.connect((HOST, PORT))

# Display connection info
print(f"Connected to server: {HOST}:{PORT}")

# Start a thread to receive messages
thread = threading.Thread(target=receive_messages, args=(client_socket,))
thread.start()

while True:
    sentence = ''
    while True:
        if msvcrt.kbhit():
            char = msvcrt.getwch()
            if char == '\r':  # Check for Enter key (carriage return)
                break
            sentence += char
            sys.stdout.write(char)
            sys.stdout.flush()
    if sentence:
        encrpyt_message = rsa.encrypt(sentence.encode(), loaded_publicKey)
        client_socket.sendto(encrpyt_message, (HOST, PORT))
        sys.stdout.write(f"\n<You> {sentence}\n")
        sys.stdout.flush()

client_socket.close()
