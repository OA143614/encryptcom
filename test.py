clients=[('127.0.0.1', 60879), ('127.0.0.1', 64283)]
#client_choice = [(('127.0.0.1', 60879), 'choice1!'), (('127.0.0.1', 64283), 'choice1!')]

#print(client_choice[0][1])
client=('127.0.0.1', 60879)
client_choice = [(('127.0.0.1', 60879), 'choice1!'), (('127.0.0.1', 64283), 'choice2!')]
sender_addr=('127.0.0.1', 60879)
""" for client in client:
    if client != ('127.0.0.1', 60879):
        print(client,client_choice[1][1]) """
for client in clients:
    print(client,sender_addr)
    if client != sender_addr:
        print(client)