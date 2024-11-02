import socket
import threading

# Server settings
HOST = '127.0.0.1'
PORT = 65432

# Create a UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Choose encryption method
encryption_method = 'unencrypted'

# Send the chosen encryption method to the server
client.sendto(encryption_method.encode('utf-8'), (HOST, PORT))

def receive_messages(client_socket):
    while True:
        try:
            message, _ = client_socket.recvfrom(4096)
            if encryption_method == 'unencrypted':
                print(f"Server: {message.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"Error receiving message: {e}")

# Start a thread to receive messages
thread = threading.Thread(target=receive_messages, args=(client,))
thread.daemon = True
thread.start()

def broadcast_message(client_socket, message):
    try:
        if encryption_method == 'unencrypted':
            client_socket.sendto(message.encode('utf-8'), (HOST, PORT))
            print(f"You: {message}")
    except Exception as e:
        print(f"Error broadcasting message: {e}")

while True:
    try:
        sentence = input("Enter message: ")
        if sentence:
            broadcast_message(client, sentence)
    except KeyboardInterrupt:
        print("\nConnection closed.")
        client.close()
        break
