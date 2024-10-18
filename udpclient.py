import socket
import threading
import msvcrt
import sys

# Server settings
HOST = '127.0.0.1'
PORT = 65432

# Function to receive messages from the server
def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024)
            if message:
                print(message.decode())
            else:
                break
        except:
            break

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

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
        client_socket.sendall(sentence.encode())
        sys.stdout.write(f"\n<You> {sentence}\n")
        sys.stdout.flush()

client_socket.close()
