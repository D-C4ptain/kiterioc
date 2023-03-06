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
        print(colored(f"Try again later\n\nError Code: {value['error']['code']}", "yellow"))
        print("")
         
                
#Scan URL
def Scan_URL(url_path):
    # get results of existing url
    print(colored("* Scanning URL...", "white"))
    URL = 'https://www.virustotal.com/api/v3/urls/'
    headers = {'x-apikey':apikey}
    url_id = base64.urlsafe_b64encode(url_path.encode()).decode().strip("=")
    import requests
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
        print(colored(f"Try again later(http/s)\nError Code: {value['error']['code']}\nUrl was not found!", "yellow"))
        print("Uploading URL....")
        
        #upload new url
        URL = "https://www.virustotal.com/api/v3/urls"
        payload = f"url={url_path}"
        headers = {
            "accept": "application/json",
            "x-apikey": apikey,
            "content-type": "application/x-www-form-urlencoded"
        }
        res = requests.post(URL, data=payload, headers=headers)
        value = res.json()
        url_id = value['data']['id'][2:-11] #remove trailing chars in url id
            
        #get analysis results
        URL = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "accept": "application/json",
            "x-apikey": apikey
        }
        res = requests.get(URL, headers=headers)
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
            print(colored(f"Try (http/s)\n\nError Code: {value['error']['code']}", "yellow"))
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
        if value['error']['code'] == "InvalidArgumentError":
            print(colored("Invalid domain name", "red"))
            print()
        else:
            print(colored(f"Try again later\n\nError Code: {value['error']['code']}", "yellow"))
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
            print(colored(f">>> This hash is clean('{Hash}').", "green"))
            print()
    else:
        if value['error']['code'] == "NotFoundError":
            print(colored(f">>> This hash is clean('{Hash}').", "green")) #ignore not found(404) files
            print()                                                       #assume is clean
        else:
            print(colored(f"Try again later\n\nError Code: {value['error']['code']}", "yellow"))
            print()


""" Upload file
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