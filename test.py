client=[('127.0.0.1', 60879), ('127.0.0.1', 64283)]
client_choice = [(('127.0.0.1', 60879), 'choice1!'), (('127.0.0.1', 64283), 'choice1!')]

#print(client_choice[0][1])
client_choice = [(('127.0.0.1', 60879), 'choice1!'), (('127.0.0.1', 64283), 'choice1!')]

for choice in client_choice:
    print(choice[1])
