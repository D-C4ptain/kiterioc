## FULL SYSTEM SCAN - Files, IP, URL, Domain, Hash

from termcolor import colored
import os
import json
import requests
import time

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
        #clear data files for new scan
        with open("mal.json", "r+") as f:
            f.seek(0)
            f.truncate()
        with open("ioc.json", "r+") as f:
            f.seek(0)
            f.truncate()
    
        print(colored("[+] Scanning file system...", "red"), "\n")    
        for root, dirs, files in os.walk(self.folder):
            if str(self.excludefolder) in os.path.join(root): #exclude a folder
                pass
            else:
                for file in files:
                    file = os.path.join(root, file)
                    print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                    print("file: ", file)        # Print file name
                    self.file = file #update file name for dumper
                    
                    # calculate file hashes
                    hash = Filehash(file)
                    print("sha256:", hash.sha256hash())
                    print("sha1:", hash.sha1hash())
                    print("MD5:", hash.md5hash())
                    time.sleep(3)
                    
                    #extract ioc from file
                    extract = Extractor(file)
                    try:
                        print(extract.ip())
                        print(extract.url())
                        print(extract.domain())
                        print(extract.email())
                        time.sleep(3)
    
                        #dump ioc to json
                        data = {
                            "filename": file, 
                            "hash": {"sha256": hash.sha256hash(), "sha1": hash.sha1hash(), "md5": hash.md5hash()},
                            "ips": extract.ip(),
                            "urls": extract.url(),
                            "domains": extract.domain(),
                            "emails": extract.email(),
                                }
                    except UnicodeDecodeError as e:
                        print("Could not extract iocs from file! \nproceeding...") # such as videos files
                    
                    #dump all scanned files
                    with open("ioc.json", "a") as f:
                        json.dump(data, f, indent = 4, sort_keys=False)
                    time.sleep(2)
                        
                    #submit file to vt
                    #Scan Hash
                    print(colored("* Scanning file(SHA-1...", "white"))
                    URL = 'https://www.virustotal.com/api/v3/files/'
                    headers = {'x-apikey':apikey}
                    hash = hash.sha1hash()
                    res = requests.get(URL + hash.strip(), headers=headers) #using sha1 hash
                    status = res.status_code
                    value = res.json()
                    if status == 200:
                        if value['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                            print(colored(f">>>This hash is malicious({hash}).", "red"))
                            with open("mal.json", "a") as f:
                                json.dump(value, f, indent = 4, sort_keys=False)
                        else:
                            print(colored(f">>> This hash is clean('{hash}').", "green"))
                    else:
                        if value['error']['code'] == "NotFoundError":
                            print(colored(f">>> This hash seems clean('{hash}').", "green")) #ignore not found(404) files                                                      #assume is clean
                        elif value['error']['code'] == "QuotaExceededError":
                            print(colored(f">>> Scan Limit reached! Try gain in a moment.", "red")) # Scan limit reached
                        else:
                            print(colored(f"Try again later\n\nError Code: {value['error']['code']}", "yellow"))
                    time.sleep(3)
        