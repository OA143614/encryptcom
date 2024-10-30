import socket
import threading
import logging

# Server settings
HOST = '127.0.0.1'
PORT = 65431

# List to keep track of connected clients
clients = []
clients_lock = threading.Lock()

# Setting up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Setting up the server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))
logging.info(f"Server listening on {HOST}:{PORT}")

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

def handle_client(addr):
    while True:
        if len(clients) == 2:
            try:
                message, addr = server.recvfrom(4096)
                if message:
                    decoded_message = message.decode('utf-8', errors='ignore')
                    sender_info = f"{addr[0]}:{addr[1]}"
                    full_message = f"{sender_info}: {decoded_message}"
                    print(f"Message from {sender_info} - {decoded_message}")
                    broadcast(full_message.encode('utf-8'), addr)
            except UnicodeDecodeError as e:
                logging.error(f"Unicode decode error: {e}")
            except Exception as e:
                logging.error(f"Error handling client message: {e}")
                with clients_lock:
                    if addr in clients:
                        clients.remove(addr)
                break

def main():
    while True:
        with clients_lock:
            if len(clients) < 2:
                # Receive message from client
                message, addr = server.recvfrom(4096)
                decoded_message = message.decode('utf-8', errors='ignore')
                print(f"Received message: {decoded_message} from {addr}")
                
                if addr not in clients:
                    clients.append(addr)
            threading.Thread(target=handle_client, args=(addr,)).start()

if __name__ == "__main__":
    main()
