""" from socket import *
serverName = 'localhost'
serverPort = 12000
clientSocket = socket(AF_INET, SOCK_DGRAM)
message = input('Input lowercase sentence:')
clientSocket.sendto(message.encode(),(serverName, serverPort))
modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
print(modifiedMessage.decode())
clientSocket.close() """

def help_func():
    print("This is chat application enter IP and port. there is 2 modes. 1 encryption 2. decryption")

while True:
    input_choice = input("Please enter:")
    if input_choice == '1':
        help_func()
    elif input_choice == '2':
        print("connection")
    elif input_choice == '3':
        print("mode")
    elif input_choice == '4':
        print("send")
    elif input_choice == '5':
        print("debug mode")
    elif input_choice =='0':
        break

