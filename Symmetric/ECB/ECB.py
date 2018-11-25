from Crypto.Cipher import AES
import configparser
import sys
import argparse
from wand.image import Image

parser = argparse.ArgumentParser(prog="python3 ECB.py", description="Encrypt or decrypt an image file (in .jpg) using ECB mode of AES")

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-e', '--encrypt', dest="enc_file", nargs=1, type=str, help="To encrypt the following image file", metavar="file_to_encrypt")
group.add_argument('-d', '--decrypt', dest="dec_file", type=str, nargs=1, help="To decrypt the following image file", metavar="file_to_decrypt")
parser.add_argument('-o', '--output', dest="out", nargs=1, type=str, help="Output file of decryption/encryption", required=True, metavar="output_file")
parser.add_argument('-c', '--config', dest="config_file", nargs=1, type=str, help="Config file containing key", required=True, metavar="config_file")
args = parser.parse_args()

pad = lambda s: s + bytes((AES.block_size - len(s) % AES.block_size) * \
                chr(AES.block_size - len(s) % AES.block_size).encode())
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def get_key(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    return config['KEY']['key']

def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    msg = cipher.encrypt(pad(message))
    return bytes(msg)

def decrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
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

    if args.enc_file:
        header, tail = get_bits_from_picture(args.enc_file[0])
        print("Getting the key....")
        key = get_key(args.config_file)
        print("Encrypting....")
        enc = encrypt(tail, key)
        store_to_file(args.out[0], header, enc)
        print("Done!")

    if args.dec_file:
        header, tail = get_bits_from_picture(args.dec_file[0])
        print("Getting the key....")
        key = get_key(args.config_file)
        print("Decrypting....")
        dec = decrypt(tail, key)
        store_to_file(args.out[0], header, dec)
        print("Done!")

if __name__ == "__main__":
    main()
