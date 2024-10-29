import socket
import threading

# Server settings
HOST = '127.0.0.1'
PORT = 65431

# Dictionary to keep track of connected clients and their choices
clients = {}
clients_lock = threading.Lock()

# Setting up the server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))
print(f"Server listening on {HOST}:{PORT}")

def broadcast(message, sender_addr):
    with clients_lock:
        for client in clients:
            if client != sender_addr:
                try:
                    server.sendto(message, client)
                except Exception as e:
                    print(f"Error sending message to {client}: {e}")
                    del clients[client]

def handle_client(addr):
    with clients_lock:
        choice = clients.get(addr)
    print(f"Handling client {addr} with choice {choice}")
    while True:
        try:
            message, _ = server.recvfrom(4096)
            if choice == 'unencrypted':
                decoded_message = message.decode('utf-8', errors='ignore')
                sender_info = f"{addr[0]}:{addr[1]}"
                full_message = f"{sender_info}: {decoded_message}"
                print(f"Message from {sender_info} - {decoded_message}")
                broadcast(full_message.encode('utf-8'), addr)
            elif choice == 'AES':
                decoded_message = message.decode('utf-8', errors='ignore')
                sender_info = f"{addr[0]}:{addr[1]}"
                full_message = f"{sender_info}: {decoded_message}"
                print(f"Message from {sender_info} - {decoded_message}")
                print("This is in AES handle")
                broadcast(full_message.encode('utf-8'), addr)
        except UnicodeDecodeError as e:
            print(f"Unicode decode error: {e}")
        except Exception as e:
            print(f"Error handling client message: {e}")
            break

while True:
    try:
        # Receive message from client
        message, addr = server.recvfrom(4096)
        decoded_message = message.decode('utf-8', errors='ignore')
        
        with clients_lock:
            if addr not in clients:
                # Treat the first message as the choice message
                clients[addr] = decoded_message
                print(f"Received choice message: {decoded_message} from {addr}")
                # Start a new thread to handle the client
                threading.Thread(target=handle_client, args=(addr,)).start()
            else:
                # Handle regular messages
                choice = clients[addr]
                if choice == 'unencrypted':
                    sender_info = f"{addr[0]}:{addr[1]}"
                    full_message = f"{sender_info}: {decoded_message}"
                    print(f"Message from {sender_info} - {decoded_message}")
                    broadcast(full_message.encode('utf-8'), addr)
                elif choice == 'AES':
                    sender_info = f"{addr[0]}:{addr[1]}"
                    full_message = f"{sender_info}: {decoded_message}"
                    print(f"Message from {sender_info} - {decoded_message}")
                    print("This is in AES handle")
                    broadcast(full_message.encode('utf-8'), addr)
    except UnicodeDecodeError as e:
        print(f"Unicode decode error: {e}")
    except Exception as e:
        print(f"Error handling client message: {e}")
