# enc_files
Encrypt/Decrypt your files. \
This small lib comes to help encrypt the content of a file and its name.\
It can also work on entire folders and their files.
##Install
`python setup.py`

##Usage

###Encrypt/decrypt single file/folder at a time
```python
from enc_files.encryptor import EncDec 
ec = EncDec("my_pass".encode("utf8"))
```
####Encrypt a file
`ec.encrypt("path/to/file_or_folder")`

####Just get the would be encrypted file name
`ec.encrypt("path/to/file_or_folder", just_name=True)`


####Decrypt a file
`ec.decrypt("path/to/file_or_folder")`

####Just get the would be decrypted file name
`ec.decrypt("path/to/file_or_folder", just_name=True)`


###Encrypt/decrypt multiple files/folders
For this task, you use a manager which dispatch encryption and decryption, and manage which files are in which state
it can do it using multiprocessing to speed things up set the number of workers (processes) to do the work.
```python
from enc_files.enc_manager import EncDecManager 
workers = 4  # Number of cpus you wish to use
manager = EncDecManager("my_pass".encode("utf8"), workers)
manager.scan_path("path/to/root/folder")
```
####Encrypt all the files
When `remove_old` is True, it will delete the original files after encrypting them.
`manager.enc_files(remove_old=True)`

####Decrypt all the files
when `remove_old` is True, it will delete the Decrypted files after decrypting them.
`manager.dec_files(remove_old=True)`

####Print paths
To print all files and folders, and if they are encrypted (with their decrypted name)or decrypted
`manager.print_paths()`\
It also prints an id number that can be used for `end_dec_by_id` function

####Encrypt files/folders by their id
To selectively encrypt/decrypt files/folder by their id, simply use `end_dec_by_id` method, and pass it a list of ids (int)
To get id numbers see [Print paths](#Print-paths)

```
id_list = [1,3,5]
manager.end_dec_by_id(id_list, remove_old=False)
```
 


