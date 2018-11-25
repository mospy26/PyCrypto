from Crypto.Cipher import AES
import configparser
import os, sys
import argparse

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
    # can only work on ppm files
    ppm_file = os.system("convert "+filepath+" "+filepath+".ppm")

    #read the data from the converted header
    with open(filepath+".ppm", "rb") as f:
        data = f.readlines()

    # Note: the "convert" command can be used too!
    header = b''.join(data[0:3]) # header of the image file not supposed to be encrypted
    tail = b''.join(data[3:]) # tail of the file to encrypt
    os.system("rm "+filepath+".ppm")
    return (header,tail)

def store_to_file(filename, header, tail):
    # write to .bin file
    with open(filename+".enc.bin", "wb") as f:
        f.write(bytes(header+tail))

    #convert .bin to .jpg
    os.system("convert "+filename+".enc.bin "+filename+ ".png")

    # remove the bin files
    os.system("rm "+filename+".enc.bin")
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
