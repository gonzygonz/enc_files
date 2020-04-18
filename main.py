import os
import time
import argparse
from multiprocessing import cpu_count
from enc_files.enc_manager import EncDecManager


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
    parser.add_argument('-v', '--verbose', action='store_true', help='print extra information')
    parser.add_argument('-j', type=int, default=max(1, (cpu_count() - 1)), help='number of multi-processors to use')
    # TODO: add flag to rename folders only, or not at all

    parser.add_argument('password')
    args = parser.parse_args()
    # pp = pprint.PrettyPrinter(indent=4, width=300)
    start = time.time()

    password = args.password.encode("utf8")
    manager = EncDecManager(password, workers=args.j, verbose=args.verbose)
    start_path = args.encrypt or args.decrypt or args.list
    if os.path.isdir(start_path):
        manager.scan_path(start_path)
        if args.encrypt:
            manager.enc_files(args.remove)
        elif args.decrypt:
            manager.dec_files(args.remove)
        elif args.list:
            manager.print_paths()
            s_ids = input("file IDs to Encrypt/Decrypt (separated by space):").split()
            try:
                i_ids = [int(f_id) for f_id in s_ids]
                manager.end_dec_by_id(i_ids, remove_old=args.remove)
            except ValueError:
                print("Not a Valid IDs: %s" % str(s_ids))

    elif os.path.isfile(start_path):
        if args.encrypt:
            manager.enc_file(start_path, args.remove)
        elif args.decrypt:
            manager.dec_file(start_path, args.remove)

    end = time.time()
    print("total: %.2fs" % (end - start))


if __name__ == '__main__':
    main()
