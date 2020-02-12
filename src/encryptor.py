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
        outFile = os.path.join(os.path.dirname(filename), "{}{}".format(ENC_SIGNATURE, (nonce + ct).replace('/', 'XXX')))
        if just_name:
            return outFile

        if os.path.isdir(filename):
            try:
                os.rename(filename, outFile)
                print("Encrypting folder name %s" % filename)
            except:
                print("could not rename %s to %s" % (filename, outFile))
                return None
            return outFile
        if os.path.isfile(outFile):
            print("Encoded version exists")
            return outFile
        print("Encrypting file %s (%d)MB" % (filename, filesize >> 20))
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
        print("Time taken: %.2fs" % (time.time() - f_start))
        return outFile

    def decrypt(self, enc_filepath: str, just_name=False) -> str:
        chunksize = 64 * 1024
        enc_filename = os.path.basename(enc_filepath)[4:].replace('XXX', '/')
        try:
            nonce = b64decode(enc_filename[0:12])
            ciphertext = b64decode(enc_filename[12:])
            cipher = ChaCha20.new(key=self.key, nonce=nonce)
            filename = cipher.decrypt(ciphertext).decode('utf-8')
        except (ValueError, KeyError):
            print("Incorrect decryption for file: %s" % enc_filepath)  # TODO: change all those prints to a logger
            return None

        outFile = os.path.join(os.path.dirname(enc_filepath), filename)
        if just_name:
            return outFile

        if os.path.isdir(enc_filepath):
            try:
                os.rename(enc_filepath, outFile)
            except:
                print("could not rename %s to %s" % (enc_filepath, outFile))
                pass
            return None

        if os.path.isfile(outFile):
            print("Decoded version Exists: %s" % outFile)
            return outFile

        with open(enc_filepath, "rb") as infile:
            filesize = infile.read(16)
            IV = infile.read(16)
            decryptor = AES.new(self.key, AES.MODE_CBC, IV)

            print("New file name: " + filename)

            with open(outFile, "wb") as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break

                    outfile.write(decryptor.decrypt(chunk))

                outfile.truncate(int(filesize))
        return outFile
