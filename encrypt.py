from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os

def generate_key(password, salt, key_length=32):
    key = PBKDF2(password, salt, dkLen=key_length, count=1000000)
    return key

def encrypt_file(key, input_file, output_file):
    chunk_size = 64 * 1024
    cipher = AES.new(key, AES.MODE_EAX)
    with open(input_file, 'rb') as infile:
        with open(output_file, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                ciphertext, tag = cipher.encrypt_and_digest(chunk)
                outfile.write(cipher.nonce)
                outfile.write(tag)
                outfile.write(ciphertext)

def decrypt_file(key, input_file, output_file):
    chunk_size = 64 * 1024
    with open(input_file, 'rb') as infile:
        with open(output_file, 'wb') as outfile:
            nonce = infile.read(16)
            tag = infile.read(16)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                outfile.write(decrypted_chunk)

if __name__ == '__main__':
    password = input('Enter password: ')
    salt = os.urandom(16)
    key = generate_key(password.encode('utf-8'), salt)

    input_file = 'plaintext.txt'
    encrypted_file = 'encrypted.txt'
    decrypted_file = 'decrypted.txt'

    encrypt_file(key, input_file, encrypted_file)
    decrypt_file(key, encrypted_file, decrypted_file)

    print("File encryption and decryption completed.")
