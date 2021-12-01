from encryptors import *
import tf
encryption_key = b"0123456789123456"
encryption_key_des = b'12345678'

# encrypt_files(encrypt_AES, encryption_key)
# input()
# decrypt_files(decrypt_AES, encryption_key)
# input()
# encrypt_files(encrypt_DES, encryption_key_des)
# input()
# decrypt_files(decrypt_DES, encryption_key_des)
# input()
tf_encrypt("twofish\\plain.txt", "twofish\\encoded.txt", '1337')
input()
tf_decrypt("twofish\\encoded.txt", "twofish\\plain2.txt", '1337')
