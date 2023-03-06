## BASIC SCAN - IP, URL, Domain, Hash

from termcolor import colored
import requests
import base64
from api_key import API_KEY

apikey = API_KEY

#Scan IP
def Scan_IP(IP):                    
    print(colored("* Scanning IP...", "white"))
    URL = 'https://www.virustotal.com/api/v3/ip_addresses/'
    headers = {'x-apikey':apikey} 
    res = requests.get(URL + IP.strip(), headers=headers)       
    status =res.status_code                            
    value = res.json()
    if status == 200:
        if value['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(colored(f">>> This IP is malicious ( {IP} ).", "red"))
            print()
        else:
            print(colored(f">>> This IP is clean ({IP}).", "green"))
            print()
    else:
        print(colored(f"Try again later\n\nError Code: {value['error']['code']}\nError Description: {value['error']['message']}", "yellow"))
        print()
        
#Scan URL
def Scan_URL(url_path):
    print(colored("* Scanning URL...", "white"))
    URL = 'https://www.virustotal.com/api/v3/urls/'
    headers = {'x-apikey':apikey}
    url_id = base64.urlsafe_b64encode(url_path.encode()).decode().strip("=")
    res = requests.get(URL + url_id.strip(), headers=headers)
    value = res.json()
    status = res.status_code
    if status == 200:
        if value['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(colored(f">>> This url is malicious ({url_path}).", "red"))
            print()
        else:
            print(colored(f">>> This url is clean ({url_path}).", "green"))
            print()
    else:
        print(colored(f"Try again later(http/s)\n\nError Code: {value['error']['code']}\nError Description: {value['error']['message']}", "yellow"))
        print()

#Scan Domain
def Scan_Domain(Domain):                
    print(colored("* Scanning Domain...", "white"))
    URL = 'https://www.virustotal.com/api/v3/domains/'
    headers = {'x-apikey':apikey}
    res = requests.get(URL + Domain.strip(), headers=headers)
    status = res.status_code
    value = res.json() 
    if status == 200:
        if value['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(colored(f">>> This domain is malicious ({Domain}).", "red"))
            print()
        else:
            print(colored(f">>> This domain is clean ({Domain}).", "green"))
            print()
    else:
        print(colored(f"Try again later\n\nError Code: {value['error']['code']}\nError Description: {value['error']['message']}", "yellow"))
        print()

#Scan Hash
def Scan_Hash(Hash):
    print(colored("* Identifying file(SHA-256, SHA-1, MD5)...", "white"))
    URL = 'https://www.virustotal.com/api/v3/files/'
    headers = {'x-apikey':apikey}
    res = requests.get(URL + Hash.strip(), headers=headers)
    status = res.status_code
    value = res.json()
    if status == 200:
        if value['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(colored(f">>>This hash is malicious({Hash}).", "red"))
            print()
        else:
            print(colored(f">>> This hash is clean('{Hash}')."), "green")
            print()
    else:
        print(colored(f"Try again later\n\nError Code: {value['error']['code']}\nError Description: {value['error']['message']}", "yellow"))
        print()
