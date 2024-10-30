import socket
import threading

# Server settings
HOST = '127.0.0.1'
PORT = 65431

# Create a UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Choose encryption method
encryption_method = input("Choose encryption method (unencrypted): ")

# Flag to stop the receiving thread
stop_thread = threading.Event()

def receive_messages(client_socket):
    #print(client_socket)
    while not stop_thread.is_set():
        try:
            message, _ = client_socket.recvfrom(4096)
            if encryption_method == 'unencrypted':
                print(f"Server: {message.decode('utf-8', errors='ignore')}")
            
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