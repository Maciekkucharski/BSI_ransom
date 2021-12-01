from twofish import Twofish

def tf_encrypt(in_filename, out_filename, password):
    infile = open(in_filename, 'r')
    outfile = open(out_filename, 'wb')
    bs = 16
    plaintext=infile.read()

    if len(plaintext)%bs:
	    padded_plaintext=str(plaintext+'%'*(bs-len(plaintext)%bs)).encode('utf-8')
    else:
	    padded_plaintext=plaintext.encode('utf-8')

    T = Twofish(str.encode(password))
    ciphertext=b''

    for x in range(int(len(padded_plaintext)/bs)):
	    ciphertext += T.encrypt(padded_plaintext[x*bs:(x+1)*bs])

    outfile.write(ciphertext)


def tf_decrypt(in_filename, out_filename, password):

    infile = open(in_filename, 'rb')
    outfile = open(out_filename, 'wb')
    
    bs = 16
    ciphertext = infile.read()
    T = Twofish(str.encode(password))
    plaintext=b''

    for x in range(int(len(ciphertext)/bs)):
        plaintext += T.decrypt(ciphertext[x*bs:(x+1)*bs])

    outfile.write(str.encode(plaintext.decode('utf-8').strip('%'))) 

tf_encrypt("twofish\\plain.txt", "twofish\\encoded.txt", '1337')
tf_decrypt("twofish\\encoded.txt", "twofish\\plain2.txt", '1337')
