import re
import socket

class Extractor:
    def __init__(self, file):
        self.file = file
    
    # extract IPs from file     
    def ip(self):
        iplist = set()
        with open(self.file) as f:
            for ip in re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', f.read()):
                try:
                    socket.inet_aton(ip)
                    iplist.add(ip)
                except socket.error:
                    pass
        return iplist


    def domain(self):
        domainlist = set()
        #extract domains from extracted emails
        for i in self.email():    
            domain = i.split('@')[1]
            domainlist.add(str(domain))
        # extract domains from file        
        with open(self.file) as f:
            string = f.readlines()
            for s in string:
                domains = re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', s)
                if domains:
                    for i in domains:
                        domainlist.add(i.split("www.")[-1])
        return domainlist
        

    # extract urls from file        
    def url(self):
        urllist = set()
        with open('test.txt') as f:
            string = f.readlines()
            for s in string:
                urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', s)
                if urls:
                    for i in urls:
                        urllist.add(i)
        return urllist


    # extract emails from file     
    def email(self):
        maillist = set()
        with open(self.file,'r') as file:
            for line in file:
                line = line.strip()
                reg = re.findall(r'[\w\.-]+@[\w\.-]+', line)
                if reg:
                    for i in reg:
                        maillist.add(i)
        return maillist
    
           