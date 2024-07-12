from scapy.layers.dot11 import Dot11Deauth, Dot11Disas
import settings
from scapy.all import *


class DeauthMon(threading.Thread):

    def __init__(self, targeted_AP, targeted_STA, att_interface):
        super(DeauthMon, self).__init__()
        self.targeted_AP = targeted_AP 
        self.targeted_STA = targeted_STA
        self.att_interface = att_interface
        
    def run(self):
        while settings.conn_loss or not settings.is_alive:
            pass
        sniff(iface=self.att_interface, store=0, stop_filter=self.stopfilter, filter=("(ether dst " + self.targeted_STA + " and ether src " + self.targeted_AP + ") or (ether dst " + self.targeted_AP + " and ether src " + self.targeted_STA + ")"))
            
            
           
    def stopfilter(self, packet):
        keyword1 = "Deauthentification"
        keyword2 = "Disassociate"
        if packet.haslayer(Dot11Deauth) or keyword1 in packet.summary():
            settings.conn_loss = True
        elif packet.haslayer(Dot11Disas) or keyword2 in packet.summary():
            settings.conn_loss = True
        else:
            pass
