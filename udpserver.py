import socket
import threading

# Server settings
HOST = '127.0.0.1'
PORT = 65432

# List to keep track of connected clients
clients = []

# Function to broadcast messages to all clients
def broadcast(message, client_socket):
    for client in clients:
        if client != client_socket:
            try:
                client.sendall(message)
            except:
                client.close()
                clients.remove(client)

# Function to handle client connections
def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(1024)
            if message:
                broadcast(message, client_socket)
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
    print(f"New connection from {addr}")
    clients.append(client_socket)
    thread = threading.Thread(target=handle_client, args=(client_socket,))
    thread.start()
