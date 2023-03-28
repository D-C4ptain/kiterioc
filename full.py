## FULL SYSTEM SCAN - Files, IP, URL, Domain, Hash

from termcolor import colored
import os
import json

from hash import Filehash
from api_key import API_KEY
from extractor import Extractor

apikey = API_KEY


class Full:
    def __init__(self, folder, excludefolder):
        self.folder = folder
        self.excludefolder = excludefolder
        self.file = ''

    def systeminfo(self):
        #https://gist.github.com/emrekgn/af9783af041edc3d508acac35dade9d2
        #https://github.com/darkwizard242/system-info
        import sysinfo


    #walk the host file system
    def filewalker(self):
        print(colored("[+] Scanning file system...", "red"), "\n")    
        for root, dirs, files in os.walk(self.folder):
            if str(self.excludefolder) in os.path.join(root): #exclude a folder
                pass
            else:
                for file in files:
                    file = os.path.join(root, file)
                    print(file)        # Print file name
                    self.file = file #update file name for dumper
                    
                    # calculate file hashes
                    hash = Filehash(file)
                    print("sha256:", hash.sha256hash())
                    print("sha1:", hash.sha1hash())
                    print("MD5:", hash.md5hash())
                    
                    #extract ioc from file
                    extract = Extractor(file)
                    try:
                        print(extract.ip(), "\n")
                        print(extract.url(), "\n")
                        print(extract.domain(), "\n")
                        print(extract.email(), "\n")
                    except UnicodeDecodeError as e:
                        print(e)
                        print("file not extractable! \nproceeding...") # videos
                    print("\n")
                    
    
                    #dump ioc to json
                    try:
                        data = {
                            "filename": file, 
                            "hash": {"sha256": hash.sha256hash(), "sha1": hash.sha1hash(), "md5": hash.md5hash()},
                            "ips": extract.ip(),
                            "urls": extract.url(),
                            "domains": extract.domain(),
                            "emails": extract.email(),
                                }
                    except UnicodeDecodeError as e:
                        print(e)
                        print("file not extractable! \nproceeding...") # videos
                    
                    #dump all scanned files
                    with open("oic.json", "a") as f:
                        json.dump(data, f, indent = 4, sort_keys=False)
                        
                    #submit file to vt
                    
        