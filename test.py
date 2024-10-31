client=[('127.0.0.1', 60879), ('127.0.0.1', 64283)]
#client_choice = [(('127.0.0.1', 60879), 'choice1!'), (('127.0.0.1', 64283), 'choice1!')]

#print(client_choice[0][1])
client_choice = [(('127.0.0.1', 60879), 'choice1!'), (('127.0.0.1', 64283), 'choice2!')]

for client in client:
    if client != ('127.0.0.1', 60879):
        print(client,client_choice[1][1])