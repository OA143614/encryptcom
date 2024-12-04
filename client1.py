import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Cipher import DES3, AES
from Cryptodome.Random import get_random_bytes
import os
import threading

ip = '127.0.0.1'
server_port = 65431  # Server port

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Define the client socket
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Set socket option to reuse the address

encryption_method = 'unencrypted'  # Default encryption method
aes_key = None
des3_key = None

display_log = False

# Function to receive messages from the server
def receive_messages():
    global encryption_method, aes_key, des3_key, display_log
    while True:
        try:
            message, _ = client.recvfrom(4096)
            if encryption_method == 'unencrypted':
                decrypted_message = message.decode('utf-8', errors='ignore')
            elif encryption_method == 'AES':
                iv_aes = message[:16]
                encrypted_message = message[16:]
                cipher = AES.new(aes_key, AES.MODE_CFB, iv_aes)
                decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8', errors='ignore')
            elif encryption_method == '3DES':
                iv_des = message[:8]
                encrypted_message = message[8:]
                cipher = DES3.new(des3_key, DES3.MODE_CFB, iv_des)
                decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8', errors='ignore')
            if display_log:
                print(f"Received message: {decrypted_message}")
            else:
                print(decrypted_message)
        except Exception as e:
            print(f"Error receiving message: {e}")

def user_interaction():
    global encryption_method, aes_key, des3_key, display_log
    port = None  # Initialize port variable
    listener_thread = None  # Initialize listener thread variable
    while True:
        choose_option = input("Please select an option: help, port, displayip, displayport, connect, mode, send, set mode, log, exit\n")
        if choose_option == 'help':
            print("Options:\n"
                  "port - Choose the port for the client\n"
                  "displayip - Show IP\n"
                  "displayport - Show port\n"
                  "connect - Connect to the server\n"
                  "mode - Choose mode for sent message.\n u - Unencrypt\n a1 - AES encryption\n a2 - 3DES encryption\n"
                  "send - send the message to another client\n"
                  "set mode - chang mode for sent message.\n u - Unencrypt\n a1 - AES encryption\n a2 - 3DES encryption\n"
                  "log - on is display log, off is display log\n"
                  "exit - exit the program\n")
        elif choose_option == 'port':
            port = input("Enter port: ")
            try:
                port = int(port)
                if 0 <= port <= 65535:
                    client.bind(('', port))  # Bind the client socket to the specified port
                    print(f"This client is accepting connections on port {port}")
                else:
                    print("Port must be in the range 0-65535.")
            except ValueError:
                print("Invalid port number. Please enter a valid integer.")
            except Exception as e:
                print(f"Failed to bind to port {port}: {e}")
        elif choose_option == 'displayip':
            print(f"IP: {ip}")
        elif choose_option == 'displayport':
            if port:
                print(f"Port: {port}")
            else:
                print("Port not set.")
        elif choose_option == 'connect':
            try:
                client.sendto(b'connect', (ip, server_port))
                if display_log:
                    print(f"Sent 'connect' to {ip}:{server_port}")
                public_pem, addr = client.recvfrom(2048)
                loaded_public_key = serialization.load_pem_public_key(public_pem)

                # Send 256-bit AES key to server encrypted with public key
                aes_key = b'\x92\x0f\xfa{\xe3u>H\xf9\x9e\x02\xc7T\xdd6\xec\xfc\x9d0\x18\xbf\x06\x9eu\x81\x90\xa1\x85T\xa6o\xf5'
                encrypted_aes_key = loaded_public_key.encrypt(
                    aes_key, 
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                client.sendto(encrypted_aes_key, (ip, server_port))

                # Generate a valid 3DES key for encryption (24 bytes)
                des3_key = b'\x7fk\x80\x8f\xba\xbc\xcbL\x97\x9b\xa7\xe9R\x0e\x0b\xdc\ry\xf7\xd3u\xfe*\xf8'
                encrypted_des3_key = loaded_public_key.encrypt(
                    des3_key, 
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                client.sendto(encrypted_des3_key, (ip, server_port))

                # Start a thread to listen for incoming messages
                listener_thread = threading.Thread(target=receive_messages)
                listener_thread.daemon = True
                listener_thread.start()

            except Exception as e:
                print(f"Failed to send 'connect': {e}")
        elif choose_option == 'mode':
            chose_encryption_method = input("Choose encryption method (u/a1/a2): ")
            if chose_encryption_method in ['u', 'a1', 'a2']:
                encryption_method = {
                    'u': 'unencrypted',
                    'a1': 'AES',
                    'a2': '3DES'
                }[chose_encryption_method]
                try:
                    client.sendto(encryption_method.encode(), (ip, server_port))
                    print(f"Sent '{encryption_method}' to {ip}:{server_port}")
                except Exception as e:
                    print(f"Failed to send '{encryption_method}': {e}")
            else:
                print("Invalid option. Please try again.")
        elif choose_option == 'set mode':
            chose_encryption_method = input("Choose encryption method (u/a1/a2): ")
            if chose_encryption_method in ['u', 'a1', 'a2']:
                encryption_method = {
                    'u': 'unencrypted',
                    'a1': 'AES',
                    'a2': '3DES'
                }[chose_encryption_method]
                try:
                    client.sendto(encryption_method.encode(), (ip, server_port))
                    if display_log:
                        print(f"Sent '{encryption_method}' to {ip}:{server_port}")
                except Exception as e:
                    print(f"Failed to send '{encryption_method}': {e}")
            else:
                print("Invalid option. Please try again.")
        elif choose_option == 'send':
            message = input("Enter message: ")
            try:
                if encryption_method == 'unencrypted':
                    sent_message = message.encode('utf-8')
                elif encryption_method == 'AES':
                    iv_aes = os.urandom(16)
                    cipher = AES.new(aes_key, AES.MODE_CFB, iv_aes)
                    sent_message = iv_aes + cipher.encrypt(message.encode('utf-8'))
                elif encryption_method == '3DES':
                    iv_des = get_random_bytes(8)
                    cipher = DES3.new(des3_key, DES3.MODE_CFB, iv_des)
                    sent_message = iv_des + cipher.encrypt(message.encode('utf-8'))
                client.sendto(sent_message, (ip, server_port))
                if display_log:
                    print(f"Sent '{message}' to {ip}:{server_port}")
                
            except Exception as e:
                print(f"Failed to send '{message}': {e}")
        elif choose_option == 'log':
            log_option = input("Choose log option (on/off): ")
            if log_option == 'on':
                display_log = True
                print("Log display is ON")
            elif log_option == 'off':
                display_log = False
                print("Log display is OFF")
            else:
                print("Invalid option. Please try again.")
        elif choose_option == 'exit':
            print("Exiting...")
            break
        else:
            print("Please input a correct command.")

user_interaction()