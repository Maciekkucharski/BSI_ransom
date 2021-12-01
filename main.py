from encryptors import *

nonce_dict = dict()
cipher_dict = dict()
tag_dict = dict()

encryption_key_aes = b"0123456789123456"
encryption_key_des = b'12345678'

choice_dict = {
    "1": encrypt_files,
    "2": decrypt_files,
}
choice_dict2 = {
    "1": encrypt_AES,
    "2": encrypt_DES,
    "3": decrypt_AES,
    "4": decrypt_DES,
}
key_dict = {
    "1": encryption_key_aes,
    "2": encryption_key_des,
    "3": encryption_key_aes,
    "4": encryption_key_des,
}

first_choice = 0
second_choice = 0
while True:
    while True:
        first_choice = input("1: encode 2: decode, 0: exit")
        if first_choice in ['0', '1', '2']:
            break
    if first_choice == '0':
        quit()
    if first_choice == '1':
        while True:
            second_choice = input("1: AES 2: DES")
            if second_choice in ['1', '2']:
                break
    else:
        while True:
            second_choice = input("3: AES 4: DES")
            if second_choice in ['3', '4']:
                break
    choice_dict[first_choice](choice_dict2[second_choice], key_dict[second_choice])
