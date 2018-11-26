from Crypto.Cipher import AES
from Crypto.Util import Counter
import configparser
import sys
import argparse
from wand.image import Image

parser = argparse.ArgumentParser(prog="python3 symmetric.py", description="Encrypt or decrypt an image file (in .jpg) using AES mode. Available options are:\nECB\nCBC\nCTR")

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-e', '--encrypt', dest="enc_file", nargs=1, type=str, help="To encrypt the following image file", metavar="file_to_encrypt")
group.add_argument('-d', '--decrypt', dest="dec_file", type=str, nargs=1, help="To decrypt the following image file", metavar="file_to_decrypt")
parser.add_argument('-o', '--output', dest="out", nargs=1, type=str, help="Output file of decryption/encryption", required=True, metavar="output_file")
parser.add_argument('-c', '--config', dest="config_file", nargs=1, type=str, help="Config file containing key", required=True, metavar="config_file")
parser.add_argument('-m', '--mode', dest="mode", nargs=1, type=str, help="Modes: ECB| CBC| CTR", required=True, metavar="mode")
args = parser.parse_args()

pad = lambda s: s + bytes((AES.block_size - len(s) % AES.block_size) * \
                chr(AES.block_size - len(s) % AES.block_size).encode())
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def get_key(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    return config['KEY']['key']

def encrypt(message, key, mode):
    cipher = AES.new(key, mode, IV="This is an IV123", counter=Counter.new(nbits=128))
    msg = cipher.encrypt(pad(message))
    return bytes(msg)

def decrypt(message, key, mode):
    cipher = AES.new(key, mode, "This is an IV123")
    dec = unpad(cipher.decrypt(message))
    return bytes(dec)

# usually used for photos
def get_bits_from_picture(filepath):

    with Image(filename=filepath) as original:
        # ppm needed
        original.format = 'ppm'
        ppm_file = original.make_blob() #get binary of the image

    header = bytes(ppm_file[:15]) # head is 15 bytes long
    tail = bytes(ppm_file[15:])

    return (header,tail)

def store_to_file(output_file, header, tail):

    f = bytes(header+tail)

    with Image(blob=f) as img:
        img.convert('png')
        img.save(filename=output_file+".png")
    return

def main():

    if len(sys.argv) <= 1:
        parser.print_help()

    modes = {'ECB': AES.MODE_ECB, 'CBC': AES.MODE_CBC, 'CTR': AES.MODE_CTR}

    if args.enc_file:
        header, tail = get_bits_from_picture(args.enc_file[0])
        print("Getting the key....")
        key = get_key(args.config_file)
        print("Encrypting....")
        enc = encrypt(tail, key, modes[args.mode[0]])
        store_to_file(args.out[0], header, enc)
        print("Done!")

    if args.dec_file:
        header, tail = get_bits_from_picture(args.dec_file[0])
        print("Getting the key....")
        key = get_key(args.config_file)
        print("Decrypting....")
        dec = decrypt(tail, key, modes[args.mode[0]])
        store_to_file(args.out[0], header, dec)
        print("Done!")

if __name__ == "__main__":
    main()
