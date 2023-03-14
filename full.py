## FULL SYSTEM SCAN - Files, IP, URL, Domain, Hash

from termcolor import colored
import os

from hash import Filehash
from api_key import API_KEY

apikey = API_KEY


class Full:
    def __init__(self, folder, excludefolder):
        self.folder = folder
        self.excludefolder = excludefolder


    def systeminfo(self):
        #https://gist.github.com/emrekgn/af9783af041edc3d508acac35dade9d2
        #https://github.com/darkwizard242/system-info
        import sysinfo


    def filewalker(self):
        print(colored("[+] Scanning file system...", "red"))    
        for root, dirs, files in os.walk(self.folder):
            if str(self.excludefolder) in os.path.join(root): #exclude a folder
                pass
            else:
                for file in files:
                    file = os.path.join(root, file)
                    print(file)        # Print file name
                    # Print file hashes
                    hash = Filehash(file)
                    print("sha256:", hash.sha256hash())
                    print("sha1:", hash.sha1hash())
                    print("MD5:", hash.md5hash())
                    print()