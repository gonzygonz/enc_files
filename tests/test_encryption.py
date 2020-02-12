import random
import string
import os
import shutil
import pytest
import src.encryptor as en


### Helper functions ###

def get_new_ec():
    __tracebackhide__ = True
    lettersAndDigits = string.ascii_letters + string.digits
    random_password = ''.join(random.choice(lettersAndDigits) for i in range(random.randint(1, 12)))
    ec = en.EncDec(random_password.encode("utf8"))
    return ec


def create_temp_workspace(path, temp_dir):
    __tracebackhide__ = True
    full_path = os.path.abspath(path)
    if os.path.isfile(full_path):
        return shutil.copy(path, temp_dir)
    else:
        return shutil.copytree(path, os.path.join(temp_dir, os.path.basename(path)))


### Test functions ###
@pytest.mark.parametrize("path", ["./tests/inputs/test1.txt", "./tests/inputs/folder_test1"])
def test_encryption_name(path, tmpdir):
    is_file = os.path.isfile(path)
    file_or_folder_exist = os.path.isfile if is_file else os.path.isdir
    file_to_test = create_temp_workspace(path, tmpdir)
    # assert 0, file_to_test
    ec = get_new_ec()
    errors = []

    new_name = ec.encrypt(file_to_test, just_name=True)
    if not file_to_test != new_name: errors.append("file name stayed the same")
    if not os.path.basename(new_name).startswith(en.ENC_SIGNATURE): errors.append(
        "Encrypted file name does not start with signature")
    if file_or_folder_exist(new_name): errors.append(
        "somehow encrypted file exists while test should only return the new name")
    if not file_or_folder_exist(file_to_test): errors.append(
        "somehow original file got deleted while test should only return the new name")

    dec_name = ec.decrypt(new_name, just_name=True)
    if not file_to_test == dec_name: errors.append("file name after decryption is not the same")
    if os.path.basename(dec_name).startswith(
            en.ENC_SIGNATURE): errors.append("Encrypted file name does not start with signature")
    if file_or_folder_exist(new_name): errors.append(
        "somehow encrypted file exists while test should only return the original name")
    if not file_or_folder_exist(
            file_to_test): errors.append(
        "somehow original file got deleted while test should only return the original name")

    ec2 = get_new_ec()
    dec_name2 = ec2.decrypt(new_name, just_name=True)
    if not dec_name2 is None: errors.append("encryption with different password gave a file name")
    if file_or_folder_exist(new_name): errors.append(
        "somehow encrypted file exists while test should only return the original name")
    if not file_or_folder_exist(
            file_to_test): errors.append(
        "somehow original file got deleted while test should only return the original name")
    assert not errors, "errors occured:\nfile: {}\n{}".format(file_to_test, "\n".join(errors))
