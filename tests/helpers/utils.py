import os
import shutil
import filecmp

### Helper functions ###
def create_temp_workspace(path, temp_dir):
    __tracebackhide__ = True
    full_path = os.path.abspath(path)
    if os.path.isfile(full_path):
        return shutil.copy(path, temp_dir)
    else:
        return shutil.copytree(path, os.path.join(temp_dir, os.path.basename(path)))


def file_or_folder_exist_illegal(is_file, should_exist, path):
    __tracebackhide__ = True
    test_func = os.path.isfile if is_file else os.path.isdir
    exists = test_func(path)
    return should_exist != exists


def lock_folder(path):
    __tracebackhide__ = True
    temp_dir_locker = os.open(os.path.join(path, 'locker_files'), os.O_RDWR | os.O_CREAT)
    return temp_dir_locker


def unlock_folder(temp_dir_locker):
    __tracebackhide__ = True
    os.close(temp_dir_locker)


def list_files_levels(path: str):
    __tracebackhide__ = True
    allFiles = {}
    allFolders = {}
    level = 0
    for root, subfiles, files in os.walk(path, topdown=False):
        for name in files:
            allFiles[name, level] = os.path.join(root, name)

        for folder in subfiles:
            allFolders[folder, level] = os.path.join(root, folder)
        level +=1
    return allFiles, allFolders


def count_dir_trees_equal(dir1, dir2):
    __tracebackhide__ = True
    equal = 0
    non_equal = 0
    semi_equal = 0
    allFiles1, allFolders1 = list_files_levels(dir1)
    allFiles2, allFolders2 = list_files_levels(dir2)

    keys_files1 = set(allFiles1.keys())
    keys_files2 = set(allFiles2.keys())
    keys_folder1 = set(allFolders1.keys())
    keys_folder2 = set(allFolders2.keys())

    non_equal += len(keys_folder1 - keys_folder2)
    non_equal += len(keys_folder2 - keys_folder1)

    equal += len(keys_folder1 & keys_folder2)

    non_equal += len(keys_files1 - keys_files2)
    non_equal += len(keys_files2 - keys_files1)

    for key in keys_files1 & keys_files2:
        if filecmp.cmp(allFiles1[key], allFiles2[key]):
            equal += 1
        else:
            semi_equal += 1

    return equal, semi_equal, non_equal