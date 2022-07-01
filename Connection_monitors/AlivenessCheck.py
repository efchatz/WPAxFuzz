import settings
import threading
from time import sleep
from Frame_types.Construct_frame_fields import bcolors
import subprocess
import os


class AllvCheck(threading.Thread):

    def __init__(self, targeted_STA, mode):
        super(AllvCheck, self).__init__()
        self.targeted_STA = targeted_STA
        self.mode = mode
             
    def run(self):
        ip_prefix = self.find_LAN_prefix()
        targeted_sta_IP = self.find_IP_of_STA(ip_prefix)
        if self.mode == 'fuzzing':
            while True:
                sleep(1)
                ping_Response = self.pingg(targeted_sta_IP)
                if ping_Response == 'found':
                    pass
                elif ping_Response == 'notfound':
                    settings.is_alive = False
                    print(f"\n{bcolors.FAIL}STA is Unresponsive{bcolors.ENDC}\n")
                    while True:
                        input(bcolors.WARNING + 'Reconnect and press Enter to resume:\n' + bcolors.ENDC)
                        if self.pingg(targeted_sta_IP) == 'found':
                            print(f"{bcolors.OKCYAN}Pausing for 20'' and procceding to the next batch of frames{bcolors.ENDC}\n")
                            sleep(20)
                            settings.is_alive = True
                            settings.conn_loss = False
                            break
        elif self.mode == 'attacking':
            while True:
                sleep(1)
                ping_Response = self.pingg(targeted_sta_IP)
                if ping_Response == 'found':
                    pass
                elif ping_Response == 'notfound':
                    settings.is_alive = False
                    
            
            
 
    def pingg(self, sta_Ip):
        try:
            sa = subprocess.check_output(['ping -f -c 1 -W 1 ' + sta_Ip + ' > /dev/null && echo found || echo notfound'], shell=True)
            sa = sa[:-1]
            return sa.decode("utf-8")
        except Exception as e:
            logger.exception(str(e))
            return '1'        
            
    def find_LAN_prefix(self):
        while True:
            print("\n\n" + bcolors.OKGREEN + "----Retrieving your ip address----" + bcolors.ENDC)
            ip_prefix = subprocess.check_output(['hostname -I | cut -d "." -f 1,2,3 '], shell=True)
            ip_prefix = ip_prefix[:-1].decode("utf-8")
            if len(ip_prefix) > 5:
                print("\nFound ip prefix: "+ ip_prefix + ' ')
                return ip_prefix
            else:
                print("Could not retrieve your ip address! Retrying in 3 seconds.")
                sleep(3)
        
    def find_IP_of_STA(self, ip_prefix):
        temp = ip_prefix
        print("\n\n" + bcolors.OKGREEN + "----Pinging all hosts with an ip prefix of: " + ip_prefix + '.xx----' + bcolors.ENDC)
        found = False
        while not found:
            sleep(0.5)
            for i in range(1,254):
                ip_prefix += '.' + str(i)
                try:
                    subprocess.call(['ping -f -c 1 -W 0.01 ' + ip_prefix + ' > /dev/null '], shell=True)
                except:
                    print("Catched. Most likely your NIC stoped working!")		
                ip_prefix = temp	
                try:	
                    sta_Ip = subprocess.check_output(['arp -a | grep '+ self.targeted_STA +' | tr -d "()" | cut -d " " -f2'], shell=True)
                    sta_Ip = sta_Ip[:-1].decode("utf-8")
                except Exception as e :
                    print("arp -a exception.")
                    sta_Ip = '1'	
                if len(sta_Ip) > 5:
                    print("\nRETRIEVED IP OF MAC: " + self.targeted_STA + "   is   " + sta_Ip + "\n" )
                    found = 1
                    responsive = self.pingg(sta_Ip)
                    while responsive == 'notfound' or responsive == '1':
                        if responsive == '1': #look at pingg function, exception has been triggered
                            print("Sleeping 10s because something went really wrong.Check your nic")
                            sleep(10)
                        else:
                            print('\n' + bcolors.WARNING + "Pinging STOPED responding" + bcolors.ENDC)
                            input(bcolors.WARNING + "Go back online and press enter: " + bcolors.ENDC)
                        responsive = self.pingg(sta_Ip)
                    print("\nSTA is responsive")
                    settings.retrieving_IP = True
                    return sta_Ip
                else: 
                    print('\n' + bcolors.FAIL + 'COULD NOT FIND IP OF MAC: ' + bcolors.ENDC + self.targeted_STA)
                    settings.IP_not_alive = True
                    settings.retrieving_IP = True
                    os._exit(0)
