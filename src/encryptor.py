from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
import os
import time

# TODO: make this 'enc_' a program argument
ENC_SIGNATURE = "enc_"


class EncDec:
    def __init__(self, key):
        self.key = SHA256.new(key).digest()

    def encrypt(self, filename: str, just_name=False):
        f_start = time.time()
        chunksize = 64 * 1024
        filesize = os.path.getsize(filename)
        IV = get_random_bytes(16)
        encryptor = AES.new(self.key, AES.MODE_CBC, IV)
        cipher = ChaCha20.new(key=self.key)
        ciphertext = cipher.encrypt(os.path.basename(filename).encode("utf8"))
        nonce = b64encode(cipher.nonce).decode('utf-8')
        ct = b64encode(ciphertext).decode('utf-8')
        outFile = os.path.join(os.path.dirname(filename), f"{ENC_SIGNATURE}{(nonce + ct).replace('/', 'XXX')}")
        if just_name:
            return outFile

        if os.path.isdir(filename):
            try:
                os.rename(filename, outFile)
                print(f"Encrypting folder name {filename}")
            except:
                print(f"could not rename {filename} to {outFile}")
                raise
            return outFile
        if os.path.isfile(outFile):
            raise FileExistsError(f"Encrypted version Exists: {outFile}")

        print(f"Encrypting file {filename} {filesize >> 20}MB")
        with open(filename, "rb") as infile:
            with open(outFile, "wb") as outfile:
                outfile.write(str(filesize).zfill(16).encode("utf8"))
                outfile.write(IV)
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - (len(chunk) % 16))

                    outfile.write(encryptor.encrypt(chunk))
        print(f"Time taken: {(time.time() - f_start):.2f}s")
        return outFile

    def decrypt(self, enc_filepath: str, just_name=False) -> str:
        f_start = time.time()
        chunksize = 64 * 1024
        enc_filename = os.path.basename(enc_filepath)[4:].replace('XXX', '/')
        try:
            nonce = b64decode(enc_filename[0:12])
            ciphertext = b64decode(enc_filename[12:])
            cipher = ChaCha20.new(key=self.key, nonce=nonce)
            filename = cipher.decrypt(ciphertext).decode('utf-8')
        except (ValueError, KeyError):
            raise ValueError(f"Incorrect decryption. Make sure password is correct for: {enc_filepath}")
            # TODO: add prints of such cases to a logger

        outFile = os.path.join(os.path.dirname(enc_filepath), filename)
        if just_name:
            return outFile

        if os.path.isdir(enc_filepath):
            try:
                os.rename(enc_filepath, outFile)
            except:
                print(f"could not rename {enc_filepath} to {outFile}")
                raise
            return outFile

        if os.path.isfile(outFile):
            raise FileExistsError(f"Decrypted version Exists: {outFile}")
            # TODO - check if we really want to raise here or return outFile
            return outFile

        with open(enc_filepath, "rb") as infile:
            filesize = infile.read(16)
            IV = infile.read(16)
            decryptor = AES.new(self.key, AES.MODE_CBC, IV)

            print(f"New file name: {filename}")

            with open(outFile, "wb") as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break

                    outfile.write(decryptor.decrypt(chunk))

                outfile.truncate(int(filesize))
        print(f"Time taken: {(time.time() - f_start):.2f}s")
        return outFile
