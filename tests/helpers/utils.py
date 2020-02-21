import os
import shutil

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