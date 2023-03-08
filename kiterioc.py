# ! /usr/bin/python3

# -*- coding: utf-8 -*-
"""
kiterioc.py - filesystem threat hunter
.. Created on 2023-01-23
.. Licence MIT
.. codeauthor:: d_captain <dcaptainkenya@gmail.com>, d-captainkenya.github.io
"""

#Cyber Threat Intelligence - Threat hunting
#check files on vt, urls, ip, domain(from mails too), emails, suspicious network observables, Map to APTs and give specific remediations according to associated TTPs
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
from extractor import Extractor

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


def filewalker(folder, excfolder):
    print(colored("[+] Scanning...", "red"))    
    for root, dirs, files in os.walk(folder):
        if str(excfolder) in os.path.join(root): #exclude a folder
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
                
#def args():
    



#xterm -e zsh -c 'echo $ZSH_VERSION; sleep 4'            

    
if __name__ == "__main__":
    
    # get command line arguments
    args = ap.ArgumentParser(description="Kiterioc - find IOCs in host system")
    args.add_argument("-B", "-b", "--basic", type=str, metavar="", help="Basic scan")
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
    basic.Scan_Domain("scdd.hawaii.edu") #iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
    basic.Scan_Hash("d41d8cd98f00b204e9800998ecf84270") #ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
    """
 
    
    #full scan and report
    #systeminfo()    
    #filewalker(arguments.folder, arguments.exclude)
    
    
    #extract ioc patterns from file
    #extract = Extractor("test.txt")
    #print(extract.ip())
    #print(extract.domain())
    #print(extract.url())
    #print(extract.email())
    
    
    #catch: keyboard, network, 