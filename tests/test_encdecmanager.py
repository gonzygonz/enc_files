import random
import string
import pytest
from enc_files import enc_manager as man
import tests.helpers.utils as ut


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
def test_manager_single_file(path, workers, tmpdir):
    file_to_test = ut.create_temp_workspace(path, tmpdir)
    manager = get_new_manager(workers)
    manager.scan_path(file_to_test)



