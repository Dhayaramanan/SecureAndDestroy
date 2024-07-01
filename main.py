# import necessary libraries
import os
import getpass

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# for raising custom error messages during encryption and decryption
class EncryptionError(Exception):
    pass


# key derivation function for derive the key suitable for encryption using user entered password
def derive_key(user_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )

    return kdf.derive(bytes(user_password, 'utf-8'))


# padding the data to make it multiple of block size used by AES encryption which is 16
def pad(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()


# this function is to unpad the padded bytes that are added to data during encryption
def unpad(data):
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()


# encryption function to encrypt the contents of the file and write the content to the same file
def encrypt(filepath, password):
    try:
        salt = os.urandom(16)
        key = derive_key(password, salt)
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES256(key), modes.CBC(iv)).encryptor()

        with open(filepath, 'rb') as f:
            data = f.read()
        encrypted_data = encryptor.update(pad(data)) + encryptor.finalize()

        with open(filepath, 'wb') as f:
            # salt and initialization vector is added to the encrypted data
            # because the same salt and initialization vector must be used to generate key for decryption.
            f.write(salt + iv + encrypted_data)
    except FileNotFoundError:
        raise EncryptionError(f'File Not Found: {filepath}')
    except PermissionError:
        raise EncryptionError(f'Permission Denied: {filepath}')
    except Exception as e:
        raise EncryptionError(f'Error: {str(e)}')


# decryption function to decrypt the file contents that are encrypted using above encryption function
def decrypt(filepath, password):
    try:
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()

        # splitting salt, initialization vector, and encrypted_data
        salt = encrypted_data[:16]  # used to generate key
        iv = encrypted_data[16:32]  # used to generate decryptor
        data = encrypted_data[32:]  # the actual encrypted data
        key = derive_key(password, salt)

        decryptor = Cipher(algorithms.AES256(key), modes.CBC(iv)).decryptor()

        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadded_data = unpad(decrypted_data)

        with open(filepath, 'wb') as f:
            f.write(unpadded_data)
    except FileNotFoundError:
        raise EncryptionError(f'File Not Found: {filepath}')
    except PermissionError:
        raise EncryptionError(f'Permission Denied for {filepath}')
    except Exception as e:
        raise EncryptionError(f'Error: {str(e)}')


# destroy function is used to encrypt the contents of the file 'n' times so that it become inaccessible
def destroy(filepath, n):
    try:
        key = os.urandom(32)
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES256(key), modes.CBC(iv)).encryptor()

        for i in range(n):
            with open(filepath, 'rb') as f:
                data = f.read()

            padded_data = pad(data)
            encrypted_message = encryptor.update(padded_data)
            with open(filepath, 'wb') as f:
                f.write(encrypted_message)
    except FileNotFoundError:
        raise EncryptionError(f'File Not Found: {filepath}')
    except PermissionError:
        raise EncryptionError(f'Permission Denied for {filepath}')
    except Exception as e:
        raise EncryptionError(f'Error: {str(e)}')


# getting the choice of operation
def get_choice():
    print('1. Encryption\n2. Decryption\n3. Destruction')
    print('> ', end='')
    return int(input())


# getting the path of the file to encrypt
def get_file_path():
    return input('Enter File Path: ').encode('unicode_escape')


# getting password which is used for encryption and decryption
def get_password():
    return getpass.getpass(prompt='Enter Password: ')


# number of times to recursively encrypt the file by the destroy function
def get_number_of_times():
    return int(input('Enter number of times to overwrite: '))


# main function
def main():
    choice = get_choice()
    if choice == 1:
        try:
            encrypt(get_file_path(), get_password())
            print("File encrypted successfully.")
        except EncryptionError as e:
            print(f"Error during encryption: {e}")
    if choice == 2:
        try:
            decrypt(get_file_path(), get_password())
            print("File decrypted successfully.")
        except EncryptionError as e:
            print(f"Error during decryption: {e}")
    if choice == 3:
        try:
            destroy(get_file_path(), get_number_of_times())
            print("Destruction Successful")
        except EncryptionError as e:
            print(f"Error during destruction: {e}")


if __name__ == '__main__':
    main()
