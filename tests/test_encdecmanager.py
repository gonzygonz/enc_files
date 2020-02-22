import random
import string
import os
import pytest
from enc_files import enc_manager as man
import tests.helpers.utils as ut
import filecmp


tests_params = [("./tests/inputs/folder_test1", 1),
                ("./tests/inputs/folder_test1", 3)]

def get_new_manager(workers=1):
    __tracebackhide__ = True
    lettersAndDigits = string.ascii_letters + string.digits
    random_password = ''.join(random.choice(lettersAndDigits) for i in range(random.randint(1, 12)))
    manager = man.EncDecManager(random_password.encode("utf8"), workers)
    return manager


### Test functions ###
@pytest.mark.parametrize("path,workers", tests_params)
def test_manager_multi_file(path, workers, tmpdir):
    work_dir = os.path.join(tmpdir,"work")
    ref_dir = os.path.join(tmpdir,"ref")
    file_to_test = ut.create_temp_workspace(path, work_dir)
    ref_path = ut.create_temp_workspace(path, ref_dir)
    errors = []
    manager = get_new_manager(workers)
    manager.scan_path(file_to_test)

    # enc files then dec and compare, with/wihtout remove
    manager.enc_files(remove_old=True)
    equal, semi_equal, non_equal = ut.count_dir_trees_equal(file_to_test, ref_path)
    if equal:
        errors.append(f"Encrypted folder came back identical to original: {equal}")
    if semi_equal:
        errors.append(f"Encrypted folder came back files with same name to original: {semi_equal}")

    manager.dec_files(remove_old=True)
    equal, semi_equal, non_equal = ut.count_dir_trees_equal(file_to_test, ref_path)
    if non_equal:
        errors.append(f"Encrypted and then decrypted folder came back  not identical to original: {non_equal}")
    if semi_equal:
        errors.append(f"Encrypted folder came back files with same name to original encryption: {semi_equal}")

    # Summarize errors
    assert not errors, f"errors occurred:\nfile: {file_to_test}\n{chr(10).join(errors)}"
