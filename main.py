from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
import os, sys, pkg_resources
import time
import argparse
from multiprocessing import Pool, cpu_count
from functools import partial
import pprint


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
        outFile = os.path.join(os.path.dirname(filename), "enc_{}".format((nonce + ct).replace('/', 'XXX')))
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


class EncPath:
    def __init__(self, path: str):
        self.orig_path = path
        self.real_path = path
        self.is_enc = os.path.basename(path).startswith("enc_")  # TODO: make this 'enc_' a program argument
        self.is_file = os.path.isfile(path)
        self.dec_name = path if not self.is_enc else None
        self.enc_name = path if self.is_enc else None

    def get_dec_name(self, enc_dec: EncDec):
        if not self.dec_name:
            self.dec_name = enc_dec.decrypt(self.orig_path, just_name=True)
        return self.dec_name

    def get_enc_name(self, enc_dec: EncDec):
        if not self.enc_name:
            self.enc_name = enc_dec.encrypt(self.orig_path, just_name=True)
        return self.enc_name

    def decrypt(self, enc_dec: EncDec):
        if self.is_enc:
            self.dec_name = enc_dec.decrypt(self.real_path)
            self.real_path = self.dec_name
            self.is_enc = False
            return self.dec_name
        return None

    def encrypt(self, enc_dec: EncDec):
        if not self.is_enc:
            self.enc_name = enc_dec.encrypt(self.real_path)
            self.real_path = self.enc_name
            self.is_enc = True
            return self.enc_name
        return None


class EncDecManager:
    def __init__(self, key, workers=1):
        self.enc_dec = EncDec(key)
        self.file_list = []
        self.workers = workers

    def scan_path(self, path: str):
        allFiles, allFolders = self.allfiles(path)
        for Tfile in allFiles + allFolders:
            self.file_list.append(EncPath(Tfile))

    def print_paths(self):
        res = self.split_to_types(convert_to_paths=True)
        pp = pprint.PrettyPrinter(indent=4, width=300)
        print("Not encrypted Files:")
        pp.pprint(res['norm_file_list'])
        print("\nNot encrypted Folders")
        pp.pprint(res['norm_folder_list'])
        print("\nEncrypted Files")
        pp.pprint(res['enc_file_list'])
        print("\nEncrypted Folders")
        pp.pprint(res['enc_folder_list'])

    def dec_file(self, path: str, remove_old=False):
        new_path = self.enc_dec.decrypt(path)
        if new_path and remove_old and path != new_path:
            os.remove(path)
        return new_path

    def enc_file(self, path: str, remove_old=False):
        new_path = self.enc_dec.encrypt(path)
        if new_path and remove_old and path != new_path:
            os.remove(path)
        return new_path

    def dec_files(self, remove_old=False):
        paths = self.split_to_types()
        self._enc_dec_list(paths['enc_file_list'], enc=False, remove_old=remove_old)

    def enc_files(self, remove_old=False):
        paths = self.split_to_types()
        self._enc_dec_list(paths['norm_file_list'], enc=True, remove_old=remove_old)

    def _enc_dec_list(self, paths, enc: bool, remove_old):
        partial_func = partial(self._launch_single_end_dec, enc, remove_old)
        with Pool(self.workers) as p:
            p.map(partial_func, paths)
            p.close()
            p.join()
            print("done files")
        # TODO: add work on folders

    def _launch_single_end_dec(self, enc: bool, remove_old: bool, path: EncPath, ):
        f_orig_path = path.real_path
        res = path.encrypt(self.enc_dec) if enc else path.decrypt(self.enc_dec)
        if res and remove_old and res != f_orig_path:
            os.remove(f_orig_path)

    @staticmethod
    def allfiles(path: str) -> (list, list):
        allFiles = []
        allFolders = []
        for root, subfiles, files in os.walk(path, topdown=False):
            for names in files:
                allFiles.append(os.path.join(root, names))
            for folder in subfiles:
                allFolders.append(os.path.join(root, folder))

        return allFiles, allFolders

    def split_to_types(self, convert_to_paths=False):
        result = {}
        result["norm_file_list"] = [f for f in self.file_list if f.is_file and (not f.is_enc)]
        result["enc_file_list"] = [f for f in self.file_list if f.is_file and f.is_enc]
        result["norm_folder_list"] = [f for f in self.file_list if (not f.is_file) and (not f.is_enc)]
        result["enc_folder_list"] = [f for f in self.file_list if (not f.is_file) and f.is_enc]
        if convert_to_paths:
            for l in result:
                result[l] = [f.get_dec_name(self.enc_dec) for f in result[l]]

        return result


def dir_path(string):
    if os.path.isdir(string):
        return string
    else:
        raise NotADirectoryError(string)


def main():
    parser = argparse.ArgumentParser(description='Enc Dec.')
    parser.version = '1.0'
    parser.description = 'small program to help encrypt/decrypt files and folders. Note this is not a really' \
                         ' secure way and is just for fun'
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', type=str, help='encrypt files')
    group.add_argument('-d', '--decrypt', type=str, help='decrypt files')
    group.add_argument('-l', '--list', type=dir_path, help='list encrypted and decrypted files')
    parser.add_argument('-r', '--remove', action='store_true', help='remove converted files')
    parser.add_argument('-j', type=int, default=max(1, (cpu_count() - 1)), help='number of multi-processors to use')
    parser.add_argument('password')
    args = parser.parse_args()
    # pp = pprint.PrettyPrinter(indent=4, width=300)
    start = time.time()

    password = args.password.encode("utf8")
    manager = EncDecManager(password, workers=args.j)
    start_path = args.encrypt or args.decrypt or args.list
    if os.path.isdir(start_path):
        manager.scan_path(start_path)
        if args.encrypt:
            manager.enc_files(args.remove)
        elif args.decrypt:
            manager.dec_files(args.remove)
        elif args.list:
            manager.print_paths()

    elif os.path.isfile(start_path):
        if args.encrypt:
            manager.enc_file(start_path, args.remove)
        elif args.decrypt:
            manager.dec_file(start_path, args.remove)

    end = time.time()
    print("total: %.2fs" % (end - start))



if __name__ == '__main__':
    main()
