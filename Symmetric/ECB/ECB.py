from Crypto.Cipher import AES
import configparser
import os
import argparse

# nargs for number of args, + means a list with an error message for empty input.
parser = argparse.ArgumentParser(prog="python3 ECB.py", description="Encrypt or decrypt an image file (in .jpg) using ECB mode of AES")
parser.add_argument('-e', '--encrypt', dest="file_to_encrypt", nargs="+", type=str, help="To encrypt the following image file")
parser.add_argument('-d', '--decrypt', dest="file_to_decrypt", type=str, nargs="+", help="To decrypt the following image file")
parser.add_argument('-o', '--output', dest="output_file", nargs=1, type=str, help="Output file of decryption", required=True)
parser.add_argument('-c', '--config', dest="config_file", nargs=1, type=str, help="Config file(s) containing key", required=True)
args = parser.parse_args()

def get_key(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    return config['KEY']['key']

def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    msg = cipher.encrypt(pad(message).encode()) if not isinstance(message, bytes) else cipher.encrypt(pad(message))
    return bytes(msg)

def decrypt(encrypted, key):
    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(encrypted).decode()
    return dec

#padding is required for ECB upto 16 bits
def pad(string):
    return string + ' '*(AES.block_size-len(string)%AES.block_size) if isinstance(string, str) else string + bytes((16-len(string)%16))

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

    #convert .bin to .png
    os.system("convert "+filename+".enc.bin "+ filename+ ".png")

    # remove the bin files
    os.system("rm "+filename+".enc.bin")
    return

def main():

    if args.file_to_encrypt:
        for file in args.file_to_encrypt:
            header, tail = get_bits_from_picture(file)
            print("Getting the key....")
            key = get_key(args.config_file)
            print("Encrypting....")
            enc = encrypt(tail, key)
            store_to_file(args.output_file[0], header, enc)
            print("Done!")

if __name__ == "__main__":
    main()
