import os
from multiprocessing import Semaphore, Process, Pipe, connection
import pprint
from collections import defaultdict
from itertools import count
from typing import Dict, List
from encryptor import EncDec


class EncPath:
    _ids = count(0)

    def __init__(self, path: str):
        self.id = next(self._ids)
        self.orig_path = path
        self.real_path = path
        self.is_enc = self.is_path_enc(path)
        self.is_file = os.path.isfile(path)
        self.dec_name = path if not self.is_enc else None
        self.enc_name = path if self.is_enc else None

    def is_path_enc(self, path):
        from encryptor import ENC_SIGNATURE
        return os.path.basename(path).startswith(ENC_SIGNATURE)

    def get_dec_name(self, enc_dec: EncDec):
        if not self.dec_name:
            self.dec_name = enc_dec.decrypt(self.real_path, just_name=True)
        return self.dec_name

    def get_enc_name(self, enc_dec: EncDec):
        if not self.enc_name:
            self.enc_name = enc_dec.encrypt(self.real_path, just_name=True)
        return self.enc_name

    def decrypt(self, enc_dec: EncDec):
        if self.is_enc:
            try:
                self.dec_name = enc_dec.decrypt(self.real_path)
            except FileExistsError:
                self.dec_name = self.get_dec_name(enc_dec)
            except ValueError:
                print("could not decrypt. bad password, log this error")
                raise
            if self.dec_name:
                self.real_path = self.dec_name
                self.is_enc = False
            return self.dec_name
        return None

    def encrypt(self, enc_dec: EncDec):
        if not self.is_enc:
            try:
                self.enc_name = enc_dec.encrypt(self.real_path)
            except FileExistsError:
                self.enc_name = self.get_enc_name(enc_dec)
            if self.enc_name:
                self.real_path = self.enc_name
                self.is_enc = True
            return self.enc_name
        return None

    def update_new_path(self, new_path):
        if not new_path:
            return None
        self.real_path = new_path
        self.is_enc = self.is_path_enc(new_path)
        if self.is_enc:
            self.enc_name = new_path
        else:
            self.dec_name = new_path
        return self.is_enc

    def update_parent_path(self, new_path, orig_path=None):
        orig_parent = os.path.dirname(self.real_path) if not orig_path else orig_path
        self.dec_name = self.dec_name.replace(orig_parent, new_path) if self.dec_name else self.dec_name
        self.enc_name = self.enc_name.replace(orig_parent, new_path) if self.enc_name else self.enc_name
        self.real_path = self.real_path.replace(orig_parent, new_path) if self.real_path else self.real_path


class EncDecManager:
    def __init__(self, key, workers=1):
        self.enc_dec = EncDec(key)
        self.file_list = []
        self.work_list = self.file_list
        self.folders_children = defaultdict(set)
        self.workers = workers

    def scan_path(self, path: str):
        allFiles, allFolders = self.allfiles(path)
        for Tfile in allFiles + allFolders:
            encpath = EncPath(Tfile)
            self.file_list.append(encpath)
            # Keep track of parents. this makes rename folders in O(n) instead of O(n^2)
            self.folders_children[os.path.dirname(Tfile)].add(encpath)

    def print_paths(self):
        res = self._convert_to_paths(self.split_to_types())
        pp = pprint.PrettyPrinter(indent=4, width=300)
        print("Not encrypted Files:")
        pp.pprint([(i, p) for (i, p, ep) in res['norm_file_list']])
        print("\nNot encrypted Folders")
        pp.pprint([(i, p) for (i, p, ep) in res['norm_folder_list']])
        print("\nEncrypted Files")
        pp.pprint(res['enc_file_list'])
        print("\nEncrypted Folders")
        pp.pprint(res['enc_folder_list'])

    def dec_file(self, path: str, remove_old=False):
        try:
            new_path = self.enc_dec.decrypt(path)
        except ValueError:
            print(f"Bad Password for {path}")
            return None
        if new_path and remove_old and path != new_path:
            os.remove(path)
        return new_path

    def enc_file(self, path: str, remove_old=False):
        try:
            new_path = self.enc_dec.encrypt(path)
        except ValueError:
            print(f"Bad Password for {path}")
            return None
        if new_path and remove_old and path != new_path:
            os.remove(path)
        return new_path

    def dec_files(self, remove_old=False):
        paths = self.split_to_types()
        # Start with files. Decoder knows not to work if decoded version exists
        self._enc_dec_list(paths['enc_file_list'], enc=False, remove_old=remove_old)

        # Now decrypt folder names
        self._enc_dec_folders(paths['enc_folder_list'], enc=False)

    def enc_files(self, remove_old=False):
        paths = self.split_to_types()
        # Start with encrypting files
        existing_enc_files = [p.get_dec_name(self.enc_dec) for p in paths['enc_file_list']]

        # Work only on files that doesnt have encrypted version yet
        files_to_enc = [p for p in paths['norm_file_list'] if p.get_dec_name(self.enc_dec) not in existing_enc_files]
        # TODO: maybe make this list subtraction with implementing == on EncPath class
        if len(files_to_enc) != len(paths['norm_file_list']):
            files_not_to_enc = [p for p in paths['norm_file_list'] if
                                p.get_dec_name(self.enc_dec) in existing_enc_files]
            pp = pprint.PrettyPrinter(indent=4, width=300)
            print("Files already encrypted:")
            pp.pprint([p.get_dec_name(self.enc_dec) for p in files_not_to_enc])
            # TODO: implement the __str__ and __repr__ for EncPath to make this easier to print
        self._enc_dec_list(files_to_enc, enc=True, remove_old=remove_old)

        # Now encrypt folder names
        self._enc_dec_folders(paths['norm_folder_list'], enc=True)

    def _enc_dec_list(self, paths, enc: bool, remove_old):
        sema = Semaphore(self.workers)
        all_processes = []
        for path in paths:
            sema.acquire()
            recv_end, send_end = Pipe(False)
            p = Process(target=self._launch_single_enc_dec, args=(enc, remove_old, path, sema, send_end))
            all_processes.append((p, recv_end, path))
            p.start()
        for p, r, path in all_processes:
            p.join()
            res = r.recv()
            path.update_new_path(res)

        print("done files")

    def _enc_dec_folders(self, paths, enc: bool):
        for folder in paths:
            f_orig_path = folder.real_path
            try:
                new_path = folder.encrypt(self.enc_dec) if enc else folder.decrypt(self.enc_dec)
                if new_path and new_path != f_orig_path:
                    # rename all sub folders to keep path correct
                    self._update_children_paths(new_path, f_orig_path)
            except ValueError as e:
                print(f"Bad Password for dir: {f_orig_path}")

    def _update_children_paths(self, new_path, old_path):
        for ch in self.folders_children[old_path]:
            # Add a new key do folder_childs with the new folder.
            self.folders_children[new_path].add(ch)
            # Update folder paths of children after folder renamed
            if not ch.is_file:
                self._update_children_paths(ch.real_path.replace(old_path, new_path), ch.real_path)
            ch.update_parent_path(new_path)

    def _launch_single_enc_dec(self, enc: bool, remove_old: bool, path: EncPath, sema: Semaphore,
                               send_msg: connection.PipeConnection):
        f_orig_path = path.real_path
        res = ""
        try:
            res = path.encrypt(self.enc_dec) if enc else path.decrypt(self.enc_dec)
            if path.is_file and res and remove_old and res != f_orig_path:
                os.remove(f_orig_path)
        except ValueError as e:
            print(f"Bad Password for file: {f_orig_path}")
        finally:
            if send_msg:
                send_msg.send(res)
            if sema:
                sema.release()

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

    def split_to_types(self, file_list=None):
        file_list = self.work_list if not file_list else file_list
        result = {
            "norm_file_list": [f for f in file_list if f.is_file and (not f.is_enc)],
            "enc_file_list": [f for f in file_list if f.is_file and f.is_enc],
            "norm_folder_list": [f for f in file_list if (not f.is_file) and (not f.is_enc)],
            "enc_folder_list": [f for f in file_list if (not f.is_file) and f.is_enc],
        }
        return result

    def _convert_to_paths(self, names_dict: Dict[str, List[EncPath]]):
        res_dict = {}
        for l in names_dict:
            res_dict[l] = [(f.id, f.get_dec_name(self.enc_dec), f.get_enc_name(self.enc_dec)) for f in names_dict[l]]
        return res_dict

    def end_dec_by_id(self, f_ids: List[int], remove_old=False):
        legal_list = [self.file_list[i] for i in f_ids if i < len(self.file_list)]
        legal_enc_list = [p for p in legal_list if not p.is_enc]
        legal_dec_list = [p for p in legal_list if p.is_enc]
        self.work_list = legal_enc_list
        self.enc_files(remove_old=remove_old)
        self.work_list = legal_dec_list
        self.dec_files(remove_old=remove_old)
        self.work_list = self.file_list