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


def file_or_folder_exist_illegal(is_file, should_exist, path):
    __tracebackhide__ = True
    test_func = os.path.isfile if is_file else os.path.isdir
    exists = test_func(path)
    return should_exist != exists


tests_params = [("./tests/inputs/test1.txt", True),
                          ("./tests/inputs/test1.txt", False),
                          ("./tests/inputs/folder_test1", True),
                          ("./tests/inputs/folder_test1", False)]


### Test functions ###
@pytest.mark.parametrize("path,just_name", tests_params)
def test_encryption_basics(path, just_name, tmpdir):
    is_file = os.path.isfile(path)
    file_to_test = create_temp_workspace(path, tmpdir)
    # assert 0, file_to_test
    ec = get_new_ec()
    errors = []

    # Test basic encryption
    new_name = ec.encrypt(file_to_test, just_name=just_name)
    if file_to_test == new_name: errors.append("File name stayed the same")

    if not os.path.basename(new_name).startswith(en.ENC_SIGNATURE): errors.append(
        "Encrypted target name does not start with signature")

    if file_or_folder_exist_illegal(is_file, not just_name, new_name): errors.append(
        f"Test used just_name={just_name} but Target was {'' if just_name else 'not '}Encrypted ")

    if file_or_folder_exist_illegal(is_file, (is_file or just_name), file_to_test): errors.append(
        f"Original file got deleted by encrypt: {file_to_test}")

    # test basic decryption
    FileExistsError_found = False
    dec_name = None
    while not dec_name:
        try:
            dec_name = ec.decrypt(new_name, just_name=just_name)
            if file_to_test != dec_name: errors.append(f"File name after decryption is not the same: {dec_name}")
        except FileExistsError as e:
            if FileExistsError_found:
                # Second time we fail on this. raise the error
                raise
            FileExistsError_found = True
            if is_file and not just_name:
                # if its a file and not only name we actually want to see this exception. delete and file and try again
                os.remove(file_to_test)
            else:
                raise

    if is_file and not just_name and not FileExistsError_found:
        errors.append("Decrypt to an existing file did not raise FileExistsError")

    if file_or_folder_exist_illegal(is_file, (is_file and not just_name), new_name): errors.append(
        f"Test used just_name={just_name} but Target was {'' if just_name else 'not '}Encrypted ")

    if file_or_folder_exist_illegal(is_file, True, file_to_test): errors.append(
        f"Original file deleted after decrypt: {file_to_test}")

    # Summarize errors
    assert not errors, f"errors occurred:\nfile: {file_to_test}\n{chr(10).join(errors)}"


@pytest.mark.parametrize("path,just_name", tests_params)
def test_encryption_bad_password(path, just_name, tmpdir):
    is_file = os.path.isfile(path)
    file_to_test = create_temp_workspace(path, tmpdir)
    # assert 0, file_to_test
    ec = get_new_ec()
    errors = []

    # Test basic encryption
    new_name = ec.encrypt(file_to_test, just_name=just_name)

    # test decryption with wrong password
    ec2 = get_new_ec()
    try:
        ec2.decrypt(new_name, just_name=just_name)
        # if we didn't catch an exception it is a mistake
        errors.append("Encryption with different password did not throw an exeption")
    except ValueError:
        pass

    if file_or_folder_exist_illegal(is_file, is_file or just_name, file_to_test): errors.append(
        f"Original file got deleted by decrypt with bad password: {file_to_test}")

    # Summarize errors
    assert not errors, f"errors occurred:\nfile: {file_to_test}\n{chr(10).join(errors)}"
