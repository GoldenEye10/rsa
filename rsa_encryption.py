#
# Student Name: Prabin Shrestha
# These are the libraries i am going to use to complete this project
import os
import easygui as eg 
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import serialization



#Prabin Shrestha
# This function uses easy gui library to get a file path using dialog box. I tried using
# tkinter to open the dialog box,, but i had some issues with it. when i looked up the issue 
# i found alternative of it Easygui to do the same task on stack overflow.
def PS_get_file_path():
    PS_file_path = eg.fileopenbox(title="Select a .txt file you want to encrypt")

    #checks if the user selected the file or there is issue fetching the filepath
    if not PS_file_path or not os.path.isfile(PS_file_path):
        eg.msgbox("No file selected or invalid file path. Please try again.", title="Error")
        return None 
    # if the correct file is selected   
    return PS_file_path  

# Student ID: T00664996
# Student Name: Prabin Shrestha
# This Function generates a public key and private key pair using rsa.generate function
def PS_generate_rsa_key_pair():
    # Generate RSA private key
    PS_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  
    # Extract the public key from the private key
    PS_public_key = PS_private_key.public_key() 

    # create private_key.pem file using write mode 
    # https://dev.to/aaronktberry/generating-encrypted-key-pairs-in-python-69b
    # I found out how to write in .pem using above link resource
    with open("private_key.pem", "wb") as f:
        f.write(PS_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # create public_key.pem file using write mode 
    # https://dev.to/aaronktberry/generating-encrypted-key-pairs-in-python-69b
    # I found out how to write in .pem using above link resource
    # I also used this documentation on who to write it in file https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#serialization-encodings
    with open("public_key.pem", "wb") as f:
        f.write(PS_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Print the private and public keys in console
    print("Private Key:")
    print(PS_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode())

    print("Public Key:")
    print(PS_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())

    return PS_private_key, PS_public_key  # Return the key pair

# Student ID: T00664996
# Student Name: Prabin Shrestha
# This Function encrypts a file using the public RSA key. It takes file path and public key as argument
# and reads the file content as binary data. Then encrpt the file using RSA then saves encrypted message 
# to same file path with .enc extension.
def PS_encrypt_file(PS_file_path, PS_public_key):
    with open(PS_file_path, 'rb') as file:
        PS_file_data = file.read()  # Read the file's content as binary data

    # Print the original message from the file
    print(f"Original message from {PS_file_path}:")
    print(PS_file_data.decode())

    # Encrypt the file data using RSA and OAEP padding with SHA-256
    # We can do this without OAEP padding and SHA-256, we can use PKCS1v15 padding isntead.
    # but its not secure as OAEP. https://cryptography.io/en/latest/development/custom-vectors/rsa-oaep-sha2/#rsa-oaep-sha2-vector-creation
    # i found the code implementing both from cryptography documentaion
    # link i shared above but i went with OAEP
    PS_encrypted_data = PS_public_key.encrypt(
        PS_file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), 
            label=None
        )
    )

    # Print the encrypted message in console
    print("Encrypted message:")
    print(PS_encrypted_data)

    # Save the encrypted data into a new file using the filepath of the .txt file
    # user selected for encoding and add .enc extension. then return encrpted file path
    PS_encrypted_file_path = PS_file_path + ".enc"
    with open(PS_encrypted_file_path, 'wb') as file:
        file.write(PS_encrypted_data)

    return PS_encrypted_file_path


# Student Name: Prabin Shrestha
# This Function decrypts a file using the private RSA key. It takes file path of encrpted file and private key as argument
# and reads the file content. Then decrpt the file using RSA then saves decrpted message 
# to same file path with .dec extension.
def PS_decrypt_file(PS_encrypted_file_path, PS_private_key):
    with open(PS_encrypted_file_path, 'rb') as file:
        PS_encrypted_data = file.read() 

    # Decrypt the file data using RSA and OAEP padding just like we did for encoding at top
    PS_decrypted_data = PS_private_key.decrypt(
        PS_encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Print the decrypted message in console
    print("Decrypted message:")
    print(PS_decrypted_data.decode())

   
    # Save the decrpted data into a new file using the filepath of the .enc file and
    # replace .enc extension with .dec. then return decrypted  file path
    PS_decrypted_file_path = PS_encrypted_file_path.replace(".enc", ".dec")
    with open(PS_decrypted_file_path, 'wb') as file:
        file.write(PS_decrypted_data)

    return PS_decrypted_file_path  



# Student Name: Prabin Shrestha
# This is the driver function where all of the above function are called to give our desired output
def main():
    # Get the file path from the dialog box
    PS_file_path = PS_get_file_path()  

    if PS_file_path: 
        PS_private_key, PS_public_key = PS_generate_rsa_key_pair()  # Generate RSA key pair

        # Encrypt the selected file and print the path of the encrypted file
        PS_encrypted_file_path = PS_encrypt_file(PS_file_path, PS_public_key)
        print(f"File encrypted and saved to {PS_encrypted_file_path}")

        # Decrypt the encrypted file and print the path of the decrypted file
        PS_decrypted_file_path = PS_decrypt_file(PS_encrypted_file_path, PS_private_key)
        print(f"File decrypted and saved to {PS_decrypted_file_path}")
    else:
        print("No valid file selected. Exiting...")
        
if __name__ == "__main__":
    main()
