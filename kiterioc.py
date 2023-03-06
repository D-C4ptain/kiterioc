# ! /usr/bin/python3

#Cyber Threat Intelligence - Threat hunting
#check file on vt, urls, ip, domain, emails, suspicious network observables, Map to APTs and give specific remediations according to associated TTPs
#soc analysts, incident responders, Malware analysts/hunters(Qres)

from termcolor import colored
from colorama import Fore, Back, Style
from datetime import datetime as dt
import sys
import os
import requests
import argparse as ap
import basic


from api_key import API_KEY
from hash import Filehash


def banner():
    print(Fore.BLUE + """  
        ##    ## #### ######## ######## ########  ####  #######   ######
        ##   ##   ##     ##    ##       ##     ##  ##  ##     ## ##    ## 
        ##  ##    ##     ##    ##       ##     ##  ##  ##     ## ##       
        #####     ##     ##    ######   ########   ##  ##     ## ##       
        ##  ##    ##     ##    ##       ##   ##    ##  ##     ## ##       
        ##   ##   ##     ##    ##       ##    ##   ##  ##     ## ##    ## 
        ##    ## ####    ##    ######## ##     ## ####  #######   ###### 
        From the hills of Kitere - https://d-captainkenya.github.io
        """)
    print(f"\t\t Started: [{dt.now()}]")
    print(Style.RESET_ALL)

def systeminfo():
    #https://gist.github.com/emrekgn/af9783af041edc3d508acac35dade9d2
    #https://github.com/darkwizard242/system-info
    import sysinfo


apikey = API_KEY








## FULL SCAN

#compile malware(a classic process injection) - https://cocomelonc.github.io/tutorial/2021/09/18/malware-injection-1.html
#x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -Wint-to-pointer-cast -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive


def hunt(folder, excfolder):
    s = colored("[+] Scanning...", "red")
    print(s)
    
    for root, dirs, files in os.walk(folder):
        for file in files:
            #if file.endswith("eicar.com"):
                # if str(excfolder) in os.path.join(root, file):
                #     pass
                # else:
            file = os.path.join(root, file)
            print("Possible malicious file found: " + file)
        
            # Print file hashes
            hash = Filehash(file)
            print("sha256:", hash.sha256hash())
            print("sha1:", hash.sha1hash())
            print("MD5:", hash.md5hash())
                
                
                
            """
            url = "https://www.virustotal.com/api/v3/files"
            headers = {    
                "X-Apikey": API_KEY
            }
            files = {'file': open(file, 'rb')}
            response = requests.post(url,files=files, headers=headers)
            #print(response.json())
            
            #get report
            res = response.json()
            fileid = res["data"]["id"]
            print(fileid)
            
            url = f"https://www.virustotal.com/api/v3/files/id"
            response = requests.post(url, files=fileid, headers=headers)
            #print(response.json())"""
                
#xterm -e zsh -c 'echo $ZSH_VERSION; sleep 4'
          
                
                

    
if __name__ == "__main__":
    try:
        # get command line arguments
        args = ap.ArgumentParser(description="Kiterioc - find IOCs in host system")
        args.add_argument("-B", "--basic", type=str, metavar="", help="Basic scan")
        args.add_argument("-F", "-V", "--full", "--verbose", type=str, metavar="", help="Verbose scan")
        args.add_argument("-f", "-p", "--folder", "--path", type=str, metavar="", help="scan folder/path, e.g. C:\\SuspiciousFiles\\") #, required=True
        args.add_argument("-e", "--exclude", type=str, metavar="", help="exclude folder, e.g. C:\\mysafefiles\\")
        args.add_argument("-v", "--version", help="show program version", action="store_true")
        arguments = args.parse_args()
        
        banner()
        
        """
        #basic
        basic.Scan_IP("192.168.3.4")
        basic.Scan_URL("https://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com")
        basic.Scan_URL("http://ic.rongovarsity.ac.ke") #flagged
        basic.Scan_Domain("45.15.156.72") #iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
        basic.Scan_Hash("d41d8cd98f00b204e9800998ecf84270") #ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
        """
    
        
        
        #full
        #systeminfo()    
        #hunt(arguments.folder, arguments.exclude)
        
    except Exception as e:
        print("Temporary failure in name resolution.")
        print(colored("Check your internet connection.", "red"))
    