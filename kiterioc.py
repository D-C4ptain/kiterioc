# ! /usr/bin/python3

# -*- coding: utf-8 -*-
"""
kiterioc.py - filesystem ioc threat hunter
.. Created on 2023-01-23
.. Licence MIT
.. codeauthor:: d_captain <dcaptainkenya@gmail.com>, dennismasila.github.io
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
from full import Full
from api_key import API_KEY
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
        From the hills of Kitere - https://dennismasila.github.io
        """)
    print(f"\t\t Started: [{dt.now()}]")
    print(Style.RESET_ALL)


def usage(): # Describe usage incase of errors
    print("please specify parameters correctly!")
    print("\nUSAGE:")
    print("\tsudo python3 kiterioc.py -flags")
    print("EXAMPLE\n\t  sudo python3 kiterioc.py -f .\n")
    print("\t  sudo python3 kiterioc.py -b -hash e7088a7c37429bd7a1e09dfd05f5052f\n")
    print("\t  sudo python3 kiterioc.py -b -ip 192.168.23.244\n")
    print("\t  sudo python3 kiterioc.py -b -url http://abc.hostname.com/somethings/anything/\n")
    
    
    sys.exit()

def input():    # get arguments
    try:
        n = len(sys.argv)
        if n < 1:
            usage()
        elif n > 1:
            if "f" in str(sys.argv[1]):
                full = Full(sys.argv[2])
                full.systeminfo()
                full.filewalker()
            elif "b" in str(sys.argv[1]) and "ip" in str(sys.argv[2]): #45.89.125.189
                basic.Scan_IP(sys.argv[3])
            elif "b" in str(sys.argv[1]) and "url" in str(sys.argv[2]):
                basic.Scan_URL(sys.argv[3])
            elif "b" in str(sys.argv[1]) and "domain" in str(sys.argv[2]): #iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
                basic.Scan_Domain(sys.argv[3])
            elif "b" in str(sys.argv[1]) and "hash" in str(sys.argv[2]):  # ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
                basic.Scan_Hash(sys.argv[3])
            else:
                usage()
                sys.exit(1)
        else:
            usage()
            sys.exit()
    except KeyboardInterrupt:
        print("\nKeyboard interrupted. \nExiting...")
        sys.exit()

    
if __name__ == "__main__":
    banner()
    input()
    
    