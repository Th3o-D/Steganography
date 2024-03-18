import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from PIL import Image
import argparse
from tqdm import tqdm

def str_to_bin(text, is_bytes=False):
    if not is_bytes:
        return [format(byte, '08b') for byte in bytes(text.encode())]
    return [format(byte, '08b') for byte in text]

def bin_to_str(bin_list, is_bytes=False):
    byte_list = [int(byte, 2) for byte in bin_list]
    bytes_content = bytes(byte_list)
    if not is_bytes:
        return bytes_content.decode()
    return bytes_content

def hide(container_path, hidden_path, outfile_path=None, key="keyfile.key", crypt=2):
    if len(os.path.basename(container_path).split(".")) == 1:
        container_path = container_path + ".png"
    if outfile_path is None:
        outfile_path = "modified_" + '.'.join(container_path.split(".")[:-1])

    container_image = Image.open(container_path)
    container_image = np.array(container_image)

    with open(hidden_path, 'rb') as file:
        to_hide = file.read()

    if crypt == 2:
        if os.path.exists(key):
            with open(key, 'rb') as filekey:
                key_pass = filekey.read()
        else:
            key_pass = Fernet.generate_key()
    elif crypt == 1:
        key_pass = key.encode()
    
    if crypt > 0:
        salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000000,
        )
        derived_password = base64.urlsafe_b64encode(kdf.derive(key_pass))
        fernet = Fernet(derived_password)
        encrypted = fernet.encrypt(to_hide)
    else:
        encrypted = to_hide
        salt = b''
    encrypted_file_bin = str_to_bin(encrypted, is_bytes=True)
    name_file_bin = str_to_bin(os.path.basename(hidden_path))
    salt_bin = str_to_bin(salt, is_bytes=True)
    
    encrypted_size = len(encrypted_file_bin)

    container_dim = container_image.shape

    # Number of bytes we can write using two least significant bits
    available_space = (container_dim[0] * container_dim[1] * container_dim[2] * 2) // 8

    # 4 bytes for indicating file size, one for indicating file name size,
    # X for storing file name with 1 < X < 127 and the remaining for the encrypted file itself
    available_space = available_space - 4 - 1 - len(name_file_bin) - len(salt_bin)

    if available_space < encrypted_size or encrypted_size > int('11111111'*4, 2):
        raise ValueError(f"Hidden file is too big\n\t- Available space :     {available_space:>15,} bytes\n\t- Encrypted file size : {encrypted_size:>15,} bytes")

    if len(name_file_bin) > 127:
        raise ValueError(f"File name too long")
    
    if len(salt_bin) > 127:
        raise ValueError(f"Salt too long")
    
    hidden_image = container_image.copy()

    container_image = container_image & int('11111100',2)
    hidden_image = hidden_image & int('00000011',2)


    file_size_bin = format(encrypted_size, '032b')
    file_size_bin = [file_size_bin[i:i+8] for i in range(0, len(file_size_bin), 8)]
    name_file_size_bin = [format(len(name_file_bin), '08b')]
    salt_size_bin = [format(len(salt_bin), '08b')]

    full_message = file_size_bin + name_file_size_bin + name_file_bin + salt_size_bin + salt_bin + encrypted_file_bin

    assert len(full_message) <= (container_dim[0] * container_dim[1] * container_dim[2] * 2) // 8

    i = 0
    j = 0
    color = 0

    pbar = tqdm(total=len(full_message))
    while len(full_message) > 0:
        while len(full_message[0]) > 0:
            paire = full_message[0][:2]
            full_message[0] = full_message[0][2:]
            
            hidden_image[i,j,color] = int(f'000000{paire}',2)

            color = (color + 1) % hidden_image.shape[2]
            if color == 0:
                j = (j + 1) % hidden_image.shape[1]
                if j == 0:
                    i = i + 1
        full_message = full_message[1:]
        pbar.update(1)
    pbar.close()
    
    container_image = container_image | hidden_image

    image = Image.fromarray(container_image)
    image.save(outfile_path + ".png")

    if crypt == 2:
        with open(key, 'wb') as filekey:
            filekey.write(key_pass)


def unhide(container_path, crypt=2, key="keyfile.key", out_dir=None):
    if not container_path.endswith('.png'):
        container_path = container_path + ".png"

    container_image = Image.open(container_path)
    container_image = np.array(container_image)

    if crypt == 2:
        if not os.path.exists(key):
            crypt = 0
        else:
            with open(key, 'rb') as filekey:
                key_pass = filekey.read()
    elif crypt == 1:
        key_pass = key.encode()
    
    full_message = []

    for i in range(container_image.shape[0]):
        for j in range(container_image.shape[1]):
            for color in range(container_image.shape[2]):
                paire = format(container_image[i,j,color], '08b')[-2:]
                if len(full_message) > 0 and len(full_message[-1]) < 8:
                    full_message[-1] = full_message[-1] + paire
                else:
                    full_message.append(paire)

    file_size_bin = int(''.join(full_message[:4]), 2)
    name_file_size_bin = int(full_message[4], 2)
    name_file_bin = full_message[5:name_file_size_bin+5]
    salt_size_bin = int(full_message[name_file_size_bin+5], 2)
    salt_bin = full_message[name_file_size_bin+6:salt_size_bin+name_file_size_bin+6]
    begin_encrypted_file = salt_size_bin+name_file_size_bin+6
    encrypted_file_bin = full_message[begin_encrypted_file:file_size_bin+begin_encrypted_file]
    if crypt > 0:
        salt_bin = bin_to_str(salt_bin, is_bytes=True)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bin,
            iterations=1000000,
        )
        derived_password = base64.urlsafe_b64encode(kdf.derive(key_pass))
        fernet = Fernet(derived_password)

    encrypted_file_bin = bin_to_str(encrypted_file_bin, is_bytes=True)

    extracted_file_name = "extracted_" + bin_to_str(name_file_bin)
    if crypt > 0:
        extracted_file = fernet.decrypt(encrypted_file_bin)
    else:
        extracted_file = encrypted_file_bin

    if out_dir is not None and os.path.isdir(out_dir):
        extracted_file_name = os.path.join(out_dir, extracted_file_name)

    with open(extracted_file_name, 'wb') as file:
        file.write(extracted_file)



def main():
    parser = argparse.ArgumentParser(description="Steganography tool for hiding and extracting files from images.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Hide command parser
    hide_parser = subparsers.add_parser("hide", help="Hide a file inside an image")
    hide_parser.add_argument("container", help="Name of the original image")
    hide_parser.add_argument("hidden_file", help="Name of the file to hide")
    hide_parser.add_argument("-o", "--outfile", help="Name of the output image (automatically defined if not provided)")
    hide_parser.add_argument("-k", "--key", default="keyfile.key", help="If crypt=2, Name of the keyfile to store the password for retrieving the file (default: keyfile.key), if crypt=1, password to encrypt the file")
    hide_parser.add_argument("-c", "--crypt", default=2, type=int, choices=[0, 1, 2], help="Indicates if the hidden file should be clear (0), encrypted with a password (1) or encrypted with a keyfile (2) (default: 2)")

    # Unhide command parser
    unhide_parser = subparsers.add_parser("unhide", help="Extract a file from an image")
    unhide_parser.add_argument("container", help="Name of the image with the hidden file")
    unhide_parser.add_argument("-k", "--key", default="keyfile.key", help="If crypt=2, Name of the keyfile containing the password (default: keyfile.key), if crypt=1, password to decrypt the file")
    unhide_parser.add_argument("-c", "--crypt", default=2, type=int, choices=[0, 1, 2], help="Indicates if the hidden file is clear (0), encrypted with a password (1) or encrypted with a keyfile (2) (default: 2)")
    unhide_parser.add_argument("-o", "--outdir", help="Name of the output directory for the extracted file")

    args = parser.parse_args()

    if args.command == "hide":
        hide(container_path=args.container, hidden_path=args.hidden_file, outfile_path=args.outfile, key=args.key, crypt=args.crypt)
    elif args.command == "unhide":
        unhide(container_path=args.container, key=args.key, crypt=args.crypt, out_dir=args.outdir)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
