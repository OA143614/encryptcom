import rsa
import sys

# Generate public and private keys
publicKey, privateKey = rsa.newkeys(512)

# Save the public key to a file
with open('public_key.pem', 'w') as file:
    file.write(publicKey.save_pkcs1().decode())

# Read the public key from the file
with open('public_key.pem', 'r') as file:
    publicKeyStr = file.read()

# Load the public key from the serialized string
loaded_publicKey = rsa.PublicKey.load_pkcs1(publicKeyStr.encode())

# This is the string that we will be encrypting
message = "hello geeks"
#printkey
print(publicKey)
print(privateKey)
# Encrypt the message with the public key
encMessage = rsa.encrypt(message.encode(), loaded_publicKey)
print("original string:", message)
print("encrypted string:", encMessage)


# Decrypt the message with the deserialized private key
decMessage = rsa.decrypt(encMessage, privateKey).decode()
print("decrypted string:", decMessage)
