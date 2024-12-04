#!/usr/bin/python
from venv import logger

from scapy.all import *

import sys
import signal
import os

import threading
import subprocess
from datetime import datetime

from scapy.layers.dot11 import Dot11Deauth, Dot11, Dot11Disas

from Mngmt_frames import SAEframes
from Mngmt_frames.SAEframes import Generate_Frames, save_State, neccessary_Tests
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

global deauth_to_Send_stop
deauth_to_Send_stop = 0


class deauth_Monitor(threading.Thread):
    def __init__(self, infos, state, deauth_Path):
        self.infos = infos
        self.state = state
        self.deauth_Path = deauth_Path

    def run(self):

        print("Started deauth monitoring!")
        sniff(iface=self.infos.ATTACKING_INTERFACE, store=0, stop_filter=self.stopfilter,
              filter="(ether dst " + self.infos.STA_MAC + " and ether src " + self.infos.AP_MAC + ") or (ether dst " + self.infos.AP_MAC + " and ether src " + self.infos.STA_MAC + ")")

    def stopfilter(self, packet):
        global deauth_to_Send_stop
        global stop_ALL_threads
        keyword = "Deauthentification"
        if stop_ALL_threads == 1:
            return True
        if packet.haslayer(Dot11Deauth) or keyword in packet.summary():

            print(bcolors.FAIL + "\nFound Deauthentication frame" + bcolors.ENDC)
            time_Found = datetime.now().strftime("%H:%M:%S")
            subprocess.call(['echo ' + str(time_Found) + '. Found deauth from ' + str(
                packet[Dot11].addr2) + ' to ' + str(
                packet[Dot11].addr1) + ' >> ' + self.deauth_Path + ' during: ' + self.state.message], shell=True)
            deauth_to_Send_stop = 1

            return False
        elif packet.haslayer(Dot11Disas):
            print(bcolors.FAIL + "\nFound Disassociation frame" + bcolors.ENDC)
            time_Found = datetime.now().strftime("%H:%M:%S")
            subprocess.call(['echo ' + str(time_Found) + '. Found disas from ' + str(
                packet[Dot11].addr2) + ' to ' + str(
                packet[Dot11].addr1) + ' >> ' + self.deauth_Path + ' during: ' + self.state.message], shell=True)
            deauth_to_Send_stop = 1
            return False
        else:
            return False


class nonresponsiveness_Monitor(threading.Thread):

    def __init__(self, infos, state, nonresponsive_Path, MONITORING_INTERFACE, targeted_STA):
        self.infos = infos
        self.state = state
        self.nonresponsive_Path = nonresponsive_Path
        self.MONITORING_INTERFACE = MONITORING_INTERFACE
        self.targeted_STA = targeted_STA

    def run(self):
        global stop_ALL_threads
        ip_prefix = self.find_my_Ip()
        sta_Ip = self.find_sta_Ip(ip_prefix)
        global start
        global toStop
        global stopThread
        stopThread = 1
        toStop = 0
        first = 0
        counter = 0
        while True:
            if stop_ALL_threads == 1:
                break
            if stopThread == 0:
                ping_Response = self.pingg(sta_Ip)

                if ping_Response == 'notfound':

                    if first == 0:
                        first = 1
                        startT = time.time()

                        new_List = list()
                        new_List.append(self.state.auth_values_to_Try)
                        new_List.append(self.state.sequence_values_to_Try)
                        new_List.append(self.state.status_values_to_Try)

                        self.state.append_Order(new_List)

                    print("Pinging STOPED responding")


                else:
                    if first == 1:
                        first = 0
                        endT = time.time()
                        time_Unresponsive = (endT - startT)
                        time_Found = datetime.now().strftime("%H:%M:%S")
                        subprocess.call(['echo ' + str(time_Found) + '. Came back online after  ' + str(
                            time_Unresponsive) + ' of unresponsivness   During: ' + self.state.message + ' >> ' + self.nonresponsive_Path],
                                        shell=True)
                    start = 1
                    print("Pinging is responding")

                time.sleep(0.5)
            else:
                toStop = 1

                print("Stoping execution until checks")
                os.kill(os.getpid(), signal.SIGUSR2)

                if first == 1:
                    ping_Response = self.pingg(sta_Ip)

                    fir = 1
                    pi = 1
                    while ping_Response == "notfound" or ping_Response == '1':

                        print("Pinging STOPED responding")
                        if fir == 1:
                            star = time.time()
                            fir = 0
                        en = time.time()
                        if en - star > 20:
                            print("calling MTI")
                            sta_Ip = self.find_sta_Ip(ip_prefix)

                        ping_Response = self.pingg(sta_Ip)

                    first = 0
                    endT = time.time()
                    time_Unresponsive = (endT - startT)
                    time_Found = datetime.now().strftime("%H:%M:%S")
                    subprocess.call(['echo ' + str(time_Found) + '. Came back online after  ' + str(
                        time_Unresponsive) + ' of unresponsivness   During: ' + self.state.message + ' >> ' + self.nonresponsive_Path],
                                    shell=True)
                time.sleep(1)
                toStop = 0
                start = 1
                stopThread = 0

    def pingg(self, sta_Ip):
        try:
            sa = subprocess.check_output([
                'ping -f -c 1 -W 1 ' + sta_Ip + ' -I ' + self.MONITORING_INTERFACE + ' > /dev/null && echo found || echo notfound'],
                shell=True)
            sa = sa[:-1]
            return sa
        except Exception as e:
            logger.exception(str(e))
            return '1'

    def find_my_Ip(self):
        while True:
            print("\n\n" + bcolors.OKGREEN + "----Retrieving your ip address----" + bcolors.ENDC)
            ip_prefix = subprocess.check_output(['hostname -I | cut -d "." -f 1,2,3 '], shell=True)
            ip_prefix = ip_prefix[:-1]
            if len(ip_prefix) > 5:
                print("Found ip prefix: " + ip_prefix + ' ')

                return ip_prefix
            else:
                print("Could not retrieve your ip address! Retrying in 3 seconds.")
                time.sleep(3)

    def find_sta_Ip(self, ip_prefix):
        temp = ip_prefix
        print(
            "\n\n" + bcolors.OKGREEN + "----Pinging all hosts with an ip prefix of: " + ip_prefix + '.xx ----' + bcolors.ENDC)
        found = 0
        fe = 1
        while found == 0:
            time.sleep(0.5)
            for i in range(1, 254):
                ip_prefix += '.' + str(i)
                try:
                    subprocess.call(
                        ['ping -f -c 1 -W 0.01 ' + ip_prefix + ' -I ' + self.MONITORING_INTERFACE + ' > /dev/null '],
                        shell=True)
                except:
                    print("Catched. Most likely your NIC stoped working!")

                ip_prefix = temp

            try:
                sta_Ip = subprocess.check_output(
                    ['arp -a | grep ' + self.infos.STA_MAC.lower() + ' | tr -d "()" | cut -d " " -f2'], shell=True)
                sta_Ip = sta_Ip[:-1]

            except Exception as e:
                print("arp -a exception.")
                sta_Ip = '1'

            if len(sta_Ip) > 5:
                print("RETRIEVED IP OF MAC: " + self.targeted_STA + "   is   " + sta_Ip + "\n")
                found = 1
                responsive = self.pingg(sta_Ip)
                while responsive == 'notfound' or responsive == '1':
                    if responsive == '1':
                        print("Sleeping 10s because something went really wrong.Check your nic")
                        time.sleep(10)
                    else:
                        print("Pinging STOPED responding")
                    responsive = self.pingg(sta_Ip)

                print("is responsive")
                return sta_Ip
            else:
                print("COULD NOT FIND IP OF MAC: " + self.targeted_STA + "... Retrying in 1 second!!")

                if self.state.message != 'sth':

                    if fe == 1:
                        fe = 0
                        print("Disconnected")

                        new_List = list()
                        new_List.append(self.state.auth_values_to_Try)
                        new_List.append(self.state.sequence_values_to_Try)
                        new_List.append(self.state.status_values_to_Try)

                        self.state.append_Dc(new_List)

                        subprocess.call(['echo DISCONNECTED >> ' + self.nonresponsive_Path], shell=True)

                time.sleep(0.5)


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

        neccessary_Tests = SAEframes.neccessary_Tests(infos)

        global start
        start = 0

        if self.CHANNEL_DIFFERENT_FREQUENCY == '00':
            print("Skipping attack on the other frequency\n")

        thread2 = deauth_Monitor(deauth_Path)
        thread2.start()
        time.sleep(1)

        if self.MONITORING_INTERFACE == '00':
            print("\nProcceding without NON-RESPONSIVNESS MONITORING!")
            start = 1
        else:
            thread1 = nonresponsiveness_Monitor(nonresponsive_Path, self.MONITORING_INTERFACE, self.att_interface)
            thread1.start()

        global stop_ALL_threads
        stop_ALL_threads = 0

        while True:

            if start == 1:
                fuzz.initiate_Fuzzing_LOGICAL_MODE()
                graphs.statisticss(nonresponsive_Path, state.order_Values)
                stop_ALL_threads = 1

                # fuzz.initiate_Fuzzing_EXTENDED_MODE()
                print("\n\nFUZZING FINISHED!")

                sys.exit(0)
                break
