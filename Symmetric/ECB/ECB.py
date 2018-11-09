from Crypto.Cipher import AES
import configparser
import os

def get_key(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    print(config['KEY']['key'])
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
    command = input("Enter a command: ")

    if len(command.split(" ")) != 3:
        print("Usage: encrypt [file] [config file with key]")
        exit(-1)

    mode, file, config_file = command.split(" ")

    if mode not in ("encrypt", "decrypt"):
        print("Usage: encrypt [file] [config file with key]")
        exit(-1)

    if mode == "encrypt":
        out_file = input("Enter output file name: ")
        header, tail = get_bits_from_picture(file)
        print("Getting the key....")
        key = get_key(config_file)
        print("Encrypting....")
        enc = encrypt(tail, key)
        store_to_file(out_file, header, enc)
        print("Done!")

if __name__ == "__main__":
    main()
