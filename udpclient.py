import socket
import threading

# Server settings
HOST = '127.0.0.1'
PORT = 65431

# Create a UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Choose encryption method
encryption_method = input("Choose encryption method (unencrypted/AES): ")

def receive_messages(client_socket):
    while True:
        try:
            message, _ = client_socket.recvfrom(4096)
            if encryption_method == 'unencrypted':
                print(f"Server: {message.decode('utf-8', errors='ignore')}")
            elif encryption_method == 'AES':
                print(f"Server: {message.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"Error receiving message: {e}")

# Start a thread to receive messages
thread = threading.Thread(target=receive_messages, args=(client,))
thread.daemon = True
thread.start()

# Send the encryption method choice once
choice_method = encryption_method.encode('utf-8')
client.sendto(choice_method, (HOST, PORT))

while True:
    try:
        sentence = input("")
        if sentence:
            if encryption_method == 'unencrypted':
                message = sentence.encode('utf-8')
                client.sendto(message, (HOST, PORT))
            elif encryption_method == 'AES':
                # Placeholder for AES encryption logic
                message = sentence.encode('utf-8')
                client.sendto(message, (HOST, PORT))
            print(f"You: {sentence}")
    except KeyboardInterrupt:
        print("\nConnection closed.")
        client.close()
        break
