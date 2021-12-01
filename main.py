from glob import glob

from Crypto.Cipher import AES
import re
from secrets import token_bytes


key = token_bytes(16)


def encrypt_AES(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipher_text, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, cipher_text, tag


def decrypt_AES(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False


def encrypt_files(encryption_method):
    nonce_dict = dict()
    cipher_dict = dict()
    tag_dict = dict()
    for file in glob("AES/to_encrypt/*.txt"):
        with open(file, "r+") as f:
            f.seek(0)
            nonce, cipher_text, tag = encryption_method(f.read())
            nonce_dict = {file: nonce}
            cipher_dict = {file: cipher_text}
            tag_dict = {file: tag}
            print(nonce_dict)
    print(nonce_dict)
    return nonce_dict, cipher_dict, tag_dict


nonce_dict, cipher_dict, tag_dict = encrypt_files(encrypt_AES)
# print(nonce_dict)
