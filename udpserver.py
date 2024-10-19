import socket
import threading

# Server settings
HOST = '127.0.0.1'
PORT = 65432

# List to keep track of connected clients
clients = []

# Function to broadcast messages to all clients
def broadcast(message, client_socket, sender_info):
    for client in clients:
        if client != client_socket:
            try:
                full_message = f"{sender_info}: {message.decode()}"
                client.sendall(full_message.encode())
            except:
                client.close()
                clients.remove(client)

# Function to handle client connections
def handle_client(client_socket, addr):
    print(f"New connection from {addr}")
    while True:
        try:
            message = client_socket.recv(1024)
            if message:
                sender_info = f"{addr[0]}:{addr[1]}"
                print(f"Message from {sender_info} - {message.decode()}")
                broadcast(message, client_socket, sender_info)
            else:
                break
        except:
            clients.remove(client_socket)
            client_socket.close()
            break

# Setting up the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()
print(f"Server listening on {HOST}:{PORT}")

while True:
    client_socket, addr = server.accept()
    clients.append(client_socket)
    thread = threading.Thread(target=handle_client, args=(client_socket, addr))
    thread.start()
