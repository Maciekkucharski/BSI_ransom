from glob import glob
from Crypto.Cipher import AES, DES

nonce_dict = dict()
cipher_dict = dict()
tag_dict = dict()


def encrypt_AES(msg, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipher_text, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, cipher_text, tag


def decrypt_AES(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False


def encrypt_DES(msg, key):
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    cipher_text, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, cipher_text, tag


def decrypt_DES(nonce, ciphertext, tag, key):
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False


def encrypt_files(encryption_method, key):
    for file in glob("AES/to_encrypt/*.txt"):
        with open(file, "r") as f:
            nonce, cipher_text, tag = encryption_method(f.read(), key)
            nonce_dict[file] = nonce
            cipher_dict[file] = cipher_text
            tag_dict[file] = tag
        with open(file, "wb") as f:
            f.write(cipher_text)


def decrypt_files(decryption_method, key):
    for file in glob("AES/to_encrypt/*.txt"):
        with open(file, "r+") as f:
            nonce = nonce_dict[file]
            tag = tag_dict[file]
            ciphertext = cipher_dict[file]
            plaintext = decryption_method(nonce, ciphertext, tag, key)
            f.truncate()
            f.write(plaintext)
