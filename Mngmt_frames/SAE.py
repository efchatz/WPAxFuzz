#!/usr/bin/python
from scapy.all import *

import sys
import signal

import subprocess
from datetime import datetime

from Mngmt_frames import SAEframes
from Mngmt_frames.SAEframes import Generate_Frames, save_State
from Msgs_colors import bcolors
from src import graphs

sys.path.append('src/')

def signal_Handler(signum, frame):
    if signum == signal.SIGUSR2:
        global toStop
        while toStop == 1:
            pass
        print("\n\n" + bcolors.OKBLUE + "STA is online" + bcolors.ENDC + "\n....Resuming execution....")
        time.sleep(1)
    else:
        pass

signal.signal(signal.SIGUSR2, signal_Handler)

# ----------------------#
class SAE:
    def __init__(self, targeted_AP, AP_CHANNEL, AP_MAC_DIFFERENT_FREQUENCY, CHANNEL_DIFFERENT_FREQUENCY, targeted_STA,
                 att_interface, MONITORING_INTERFACE, PASSWORD):
        super(SAE, self).__init__()
        self.targeted_AP = targeted_AP
        self.AP_CHANNEL = AP_CHANNEL
        self.AP_MAC_DIFFERENT_FREQUENCY = AP_MAC_DIFFERENT_FREQUENCY
        self.CHANNEL_DIFFERENT_FREQUENCY = CHANNEL_DIFFERENT_FREQUENCY
        self.targeted_STA = targeted_STA
        self.att_interface = att_interface
        self.MONITORING_INTERFACE = MONITORING_INTERFACE
        self.PASSWORD = PASSWORD

    def fuzz_sae(self):

        infos = Generate_Frames(self.targeted_AP, self.AP_CHANNEL, self.AP_MAC_DIFFERENT_FREQUENCY,
                                self.CHANNEL_DIFFERENT_FREQUENCY,
                                self.targeted_STA, self.att_interface, self.MONITORING_INTERFACE, self.PASSWORD)

        folder_Name = datetime.now().strftime("fuzz%d-%m-%y__%H:%M:%S")
        folder_Path = 'Logs/' + folder_Name
        deauth_Path = folder_Path + '/Deauth.txt'
        nonresponsive_Path = folder_Path + '/Nonresponsive.txt'

        subprocess.call(['mkdir -m 777 -p Logs'], shell=True)
        subprocess.call(['mkdir -m 777 ' + folder_Path], shell=True)
        subprocess.call(['touch ' + deauth_Path + ' && chmod 777 ' + deauth_Path], shell=True)
        subprocess.call(['touch ' + nonresponsive_Path + ' && chmod 777 ' + nonresponsive_Path], shell=True)

        state = save_State()

        fuzz = SAEframes.fuzz(infos, state, self.MONITORING_INTERFACE, self.CHANNEL_DIFFERENT_FREQUENCY)

        SAEframes.neccessary_Tests(infos)

        global start
        start = 0

        if self.CHANNEL_DIFFERENT_FREQUENCY == '00':
            print("Skipping attack on the other frequency\n")

        time.sleep(1)

        if self.MONITORING_INTERFACE == '00':
            print("\nProcceding without NON-RESPONSIVNESS MONITORING!")
            start = 1

        while True:

            if start == 1:
                fuzz.initiate_Fuzzing_LOGICAL_MODE()
                graphs.statisticss(nonresponsive_Path, state.order_Values)

                # fuzz.initiate_Fuzzing_EXTENDED_MODE()
                print("\n\nFUZZING FINISHED!")

                sys.exit(0)
                break
