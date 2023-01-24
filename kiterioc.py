# ! /usr/bin/python3

from colorama import Fore, Back, Style

def banner():
    print(Fore.RED + """  
        ##    ## #### ######## ######## ########  ####  #######   ######
        ##   ##   ##     ##    ##       ##     ##  ##  ##     ## ##    ## 
        ##  ##    ##     ##    ##       ##     ##  ##  ##     ## ##       
        #####     ##     ##    ######   ########   ##  ##     ## ##       
        ##  ##    ##     ##    ##       ##   ##    ##  ##     ## ##       
        ##   ##   ##     ##    ##       ##    ##   ##  ##     ## ##    ## 
        ##    ## ####    ##    ######## ##     ## ####  #######   ###### 
        From the hills of Kitere - https://d-captainkenya.github.io
        """)
    print(Style.RESET_ALL)

def systeminfo():
    #https://gist.github.com/emrekgn/af9783af041edc3d508acac35dade9d2
    #https://github.com/darkwizard242/system-info
        
    import sysinfo
    











def hunt():
    return 0
    
def help():
    return 0
    
    
if __name__ == "__main__":
    banner()
    systeminfo()
    hunt()
    # if args
    help()