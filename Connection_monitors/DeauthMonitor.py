import settings
import threading
from time import sleep
from scapy.all import *
from Frame_types.Construct_frame_fields import bcolors


class DeauthMon(threading.Thread):

    def __init__(self, targeted_AP, targeted_STA, att_interface, mode):
        super(DeauthMon, self).__init__()
        self.targeted_AP = targeted_AP 
        self.targeted_STA = targeted_STA
        self.att_interface = att_interface
        self.mode = mode
        
    def run(self):
        while settings.conn_loss or not settings.is_alive:
            pass
        sniff(iface=self.att_interface, store=0, stop_filter=self.stopfilter, filter=("(ether dst " + self.targeted_STA + " and ether src " + self.targeted_AP + ") or (ether dst " + self.targeted_AP + " and ether src " + self.targeted_STA + ")"))
            
            
           
    def stopfilter(self, packet):
        keyword1 = "Deauthentification"
        keyword2 = "Disassociate"
        if packet.haslayer(Dot11Deauth) or keyword1 in packet.summary():
            settings.conn_loss = True
            self.resume_fuzz()
        elif packet.haslayer(Dot11Disas) or keyword2 in packet.summary():
            settings.conn_loss = True
            self.resume_fuzz()
        else:
            pass
            
            
            
    def resume_fuzz(self):
        if self.mode == 'fuzzing':
            input(f'\n{bcolors.FAIL}Deauth or Disass frame found.{bcolors.ENDC}\n\n{bcolors.WARNING}Reconnect, if needed, and press Enter to resume:{bcolors.ENDC}\n')
            print(f"{bcolors.OKCYAN}Pausing for 10'' and procceding to the next batch of frames{bcolors.ENDC}\n")
            sleep(10)
            settings.conn_loss = False
            settings.is_alive = True   
        elif self.mode == 'attacking':
            pass

            
