# calculate hash of file object
import hashlib
import time

class Filehash:
    def __init__(self, file):
        self.file = file
        
        
    def sha256hash(self):
        time.sleep(2)
        sha256 = hashlib.sha256()
        try:
            with open(self.file,'rb') as f:
                # Read and update hash value in blocks of 4K to avoid buffer overflow
                for byte_block in iter(lambda: f.read(4096),b""):
                        sha256.update(byte_block)
        except FileNotFoundError: #broken linux symlinks
            pass
        return sha256.hexdigest()
    
    
    def sha1hash(self):
        time.sleep(2)
        sha1 = hashlib.sha1()
        try:
            with open(self.file,'rb') as f:
                chunk = 0   # loop till the end of the file
                while chunk != b'':
                    chunk = f.read(1024)     # read only 1024 bytes at a time
                    sha1.update(chunk)
        except FileNotFoundError: #broken linux symlinks
            pass
        return sha1.hexdigest()


    def md5hash(self):
        time.sleep(2)
        SIZE = 32768
        md5 = hashlib.md5()
        try:
            with open (self.file,'rb') as f:
                while True:
                    data = f.read(SIZE)
                    if not data:
                        break
                    md5.update(data)
        except FileNotFoundError: #broken linux symlinks
            pass
        return md5.hexdigest()