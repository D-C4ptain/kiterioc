import re

class Extractor:
    def __init__(self, file):
        self.file = file
    
    def ip(self):
        iplist = []
        with open(self.file) as f:
            string = f.readlines()
            for line in string:
                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
                if ip:
                    for i in ip:
                        iplist.append(i)
        return iplist


    def domain(self):
        fduguewgf
        

    def url(self):
        fduguewgf
        

    def email(self):
        fduguewgf
    




                