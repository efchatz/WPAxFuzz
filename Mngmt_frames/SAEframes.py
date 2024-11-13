import subprocess
import sys
import threading
from datetime import time

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Auth
from scapy.sendrecv import sendp, srp1, sniff

from Msgs_colors import bcolors
from src import saee


class Generate_Frames:

    def __init__(self, AP_MAC, AP_CHANNEL, AP_MAC_DIFFERENT, CHANNEL_DIFFERENT, STA_MAC, ATTACKING_INTERFACE,
                 MONITORING_INTERFACE, PASSWORD):

        self.AP_MAC = AP_MAC
        self.AP_CHANNEL = AP_CHANNEL
        self.AP_MAC_DIFFERENT = AP_MAC_DIFFERENT
        self.CHANNEL_DIFFERENT = CHANNEL_DIFFERENT
        self.STA_MAC = STA_MAC
        self.ATTACKING_INTERFACE = ATTACKING_INTERFACE
        self.MONITORING_INTERFACE = MONITORING_INTERFACE
        self.PASSWORD = PASSWORD

    def generate_Authbody(self, auth_Algorithm, sequence_Number, status1):

        auth_Body = RadioTap() / Dot11(type=0, subtype=11, addr1=self.AP_MAC, addr2=self.STA_MAC,
                                       addr3=self.AP_MAC) / Dot11Auth(algo=auth_Algorithm, seqnum=sequence_Number,
                                                                      status=status1)
        return auth_Body

    def generate_valid_Commit_Authbody(self):
        auth_Body = self.generate_Authbody(3, 1, 0)
        return auth_Body

    def generate_valid_Confirm_Authbody(self):
        auth_Body = self.generate_Authbody(3, 2, 0)
        return auth_Body

    def generate_Group(self):
        group = '\x13\x00'
        return group

    def generate_send_Confirm(self, valid):
        if valid == 0:
            send = '\x00\x00'
        if valid == 1:
            send = '\x00\x02'
        return send

    def generate_payload_Confirm(self):
        confirm = 'something'
        return confirm

    def generate_Custom_Commit(self, auth, seq, stat):
        body = self.generate_Authbody(auth, seq, stat)
        group = self.generate_Group()
        print(self.STA_MAC.upper() + self.AP_MAC.upper())
        scalar, finite = saee.generate_Scalar_Finite(self.PASSWORD, self.STA_MAC.upper(), self.AP_MAC.upper())
        frame = body / group / scalar / finite
        return frame

    def generate_Custom_Confirm(self, auth, seq, stat, valid):
        body = self.generate_Authbody(auth, seq, stat)
        send = self.generate_send_Confirm(valid)
        confirm = self.generate_payload_Confirm()
        frame = body / send / confirm
        return frame

    def generate_correct_Commit(self):
        auth_Body = self.generate_valid_Commit_Authbody()
        group = self.generate_Group()
        scalar, finite = saee.generate_Scalar_Finite(self.PASSWORD, self.STA_MAC, self.AP_MAC)
        frame = auth_Body / group / scalar / finite
        return frame

    def send_Frame(self, frame, burst_Number):

        sendp(frame, count=burst_Number, iface=self.ATTACKING_INTERFACE, verbose=0)

    def change_to_diff_Frequency(self):

        temp_Mac = self.AP_MAC
        self.AP_MAC = self.AP_MAC_DIFFERENT
        self.AP_MAC_DIFFERENT = temp_Mac

        temp_Channel = self.AP_CHANNEL
        self.AP_CHANNEL = self.CHANNEL_DIFFERENT
        self.CHANNEL_DIFFERENT = temp_Channel

        subprocess.call(['iwconfig ' + self.ATTACKING_INTERFACE + ' channel ' + self.AP_CHANNEL], shell=True)
        current_Channel = subprocess.check_output(
            ['iw ' + self.ATTACKING_INTERFACE + ' info | grep channel | cut -d " " -f2'], shell=True)

        print('\nAP_MAC changed to: ' + self.AP_MAC + '\nChannel changed to: ' + current_Channel)

    def toString(self):
        print('AP_MAC: ' + self.AP_MAC)
        print('AP_CHANNEL: ' + self.AP_CHANNEL)
        print('AP_MAC_DIFFERENT: ' + self.AP_MAC_DIFFERENT)
        print('CHANNEL_DIFFERENT: ' + self.CHANNEL_DIFFERENT)
        print('STA_MAC: ' + self.STA_MAC)
        print('ATTACKING_INTERFACE: ' + self.ATTACKING_INTERFACE)
        print('MONITORING_INTERFACE: ' + self.MONITORING_INTERFACE)


class save_State:
    def __init__(self):

        self.order_Values = []
        self.dc_values = []
        self.frames_to_Send = 1
        self.auth_values_to_Try = 0
        self.sequence_values_to_Try = 1
        self.status_values_to_Try = 0
        self.identifier = 0
        self.message = 'sth'

    def setValues(self, frames_to_Send, auth_values_to_Try, sequence_values_to_Try, status_values_to_Try, identifier):
        self.frames_to_Send = frames_to_Send
        self.auth_values_to_Try = auth_values_to_Try
        self.sequence_values_to_Try = sequence_values_to_Try
        self.status_values_to_Try = status_values_to_Try
        self.identifier = identifier

    def __eq__(self, other):
        return self.message == other.message

    def append_Order(self, listt):
        found = 0
        if not self.order_Values:
            self.order_Values.append(listt)
        else:
            for a in self.order_Values:
                if a[0] == listt[0] and a[1] == listt[1] and a[2] == listt[2]:
                    found = 1
            if found == 0:
                self.order_Values.append(listt)

    def append_Dc(self, listt):
        found = 0
        if not self.dc_values:
            self.dc_values.append(listt)
        else:
            for a in self.dc_values:
                if a[0] == listt[0] and a[1] == listt[1] and a[2] == listt[2]:
                    found = 1
                    break
            if found == 0:
                self.dc_values.append(listt)


class fuzz:

    def __init__(self, infos, state, MONITORING_INTERFACE, CHANNEL_DIFFERENT_FREQUENCY):
        self.total_frames_to_Send = 50

        self.auth_values_to_Try = [0, 1, 2, 3, 200]
        self.sequence_values_to_Try = [1, 2, 3, 4, 200]
        self.status_values_to_Try = [0, 1, 200]
        self.infos = infos
        self.state = state
        self.monitoring_interface = MONITORING_INTERFACE
        self.channel_different_frequency = CHANNEL_DIFFERENT_FREQUENCY

    def construct_and_Send(self, identifier, burst_Number):
        global stopThread
        time.sleep(0.01)

        for auth_value in self.auth_values_to_Try:
            for sequence_value in self.sequence_values_to_Try:
                for status_value in self.status_values_to_Try:
                    self.state.setValues(self.total_frames_to_Send, auth_value, sequence_value, status_value,
                                         identifier)

                    self.sendd(auth_value, sequence_value, status_value, identifier, burst_Number)

    def construct_and_Send2(self, identifier):

        time.sleep(10)
        for a in self.state.order_Values:
            auth_valuee = a[0]
            self.state.auth_values_to_Try = auth_valuee

            sequence_valuee = a[1]
            self.state.sequence_values_to_Try = sequence_valuee

            status_value = a[2]
            self.state.status_values_to_Try = status_value

            self.sendd(auth_valuee, sequence_valuee, status_value, identifier, 128)

    def fuzz_Empty_Bodies(self, burst_Number):
        self.construct_and_Send(1, burst_Number)

    def fuzz_validCommit_EmptyBodies(self, burst_Number):
        self.construct_and_Send(2, burst_Number)

    def fuzz_validCommit_goodConfirm(self, burst_Number):
        self.construct_and_Send(3, burst_Number)

    def fuzz_validCommit_badConfirm(self, burst_Number):
        self.construct_and_Send(4, burst_Number)

    def fuzz_Commit(self, burst_Number):
        self.construct_and_Send(5, burst_Number)

    def fuzz_goodConfirm(self, burst_Number):
        self.construct_and_Send(6, burst_Number)

    def fuzz_badConfirm(self, burst_Number):
        self.construct_and_Send(7, burst_Number)

    def cyrcle1(self):

        self.fuzz_Empty_Bodies(1)
        self.fuzz_validCommit_EmptyBodies(1)
        self.fuzz_validCommit_goodConfirm(1)
        self.fuzz_validCommit_badConfirm(1)
        self.fuzz_Commit(1)
        self.fuzz_goodConfirm(1)
        self.fuzz_badConfirm(1)

    def cyrcle2(self):
        time.sleep(1)
        self.cyrcle1()

    def cyrcle3(self):

        time.sleep(1)
        self.construct_and_Send2(1)
        self.construct_and_Send2(2)
        self.construct_and_Send2(3)
        self.construct_and_Send2(4)
        self.construct_and_Send2(5)
        self.construct_and_Send2(6)
        self.construct_and_Send2(7)

        time.sleep(1)

    def cyrcle4(self):
        self.cyrcle3()

    def initiate_Fuzzing_LOGICAL_MODE(self):
        self.cyrcle1()
        if self.channel_different_frequency != '00':
            self.infos.change_to_diff_Frequency()
            self.cyrcle2()
            self.infos.change_to_diff_Frequency()

        self.cyrcle3()

        if self.channel_different_frequency != '00':
            self.infos.change_to_diff_Frequency()
            self.cyrcle4()
            self.infos.change_to_diff_Frequency()

    def initiate_Fuzzing_EXTENSIVE_MODE(self):
        self.auth_values_to_Try = list(range(0, 65534))
        self.sequence_values_to_Try = list(range(0, 65534))
        self.status_values_to_Try = list(range(0, 65534))
        self.initiate_Fuzzing_LOGICAL_MODE()

    def sendd(self, auth_value, sequence_value, status_value, identifier, burst_Number):
        global stopThread
        global deauth_to_Send_stop
        deauth_to_Send_stop = 0
        toprint = 1
        stopThread = 0
        firs = 1
        self.total_frames_to_Send = 50

        for times in range(0, self.total_frames_to_Send):

            if identifier == 1:
                if firs == 1:
                    frame = self.infos.generate_Authbody(auth_value, sequence_value, status_value)
                    firs = 0
                message = " eempty body frames with values : "

                self.infos.send_Frame(frame, burst_Number)
            elif identifier == 2:
                if firs == 1:
                    self.total_frames_to_Send = 25
                    frame = self.infos.generate_Custom_Commit(3, 1, 0)
                    frame2 = self.infos.generate_Authbody(auth_value, sequence_value, status_value)
                    firs = 0
                message = " valid commits folowed by empty body frames with values: "
                self.infos.send_Frame(frame, burst_Number)
                time.sleep(0.05)
                self.infos.send_Frame(frame2, burst_Number)
            elif identifier == 3:
                if firs == 1:
                    self.total_frames_to_Send = 25
                    frame = self.infos.generate_Custom_Commit(3, 1, 0)
                    frame2 = self.infos.generate_Custom_Confirm(auth_value, sequence_value, status_value, 0)
                    firs = 0
                message = " valid commits folowed by confirm with send-confirm value = 0 ,, with body values : "
                self.infos.send_Frame(frame, burst_Number)
                time.sleep(0.05)
                self.infos.send_Frame(frame2, burst_Number)
            elif identifier == 4:
                if firs == 1:
                    self.total_frames_to_Send = 25
                    frame = self.infos.generate_Custom_Commit(3, 1, 0)
                    frame2 = self.infos.generate_Custom_Confirm(auth_value, sequence_value, status_value, 1)
                    firs = 0
                message = " valid commits folowed by confirm with send-confirm value = 2 ,, with body values : "
                self.infos.send_Frame(frame, burst_Number)
                time.sleep(0.05)
                self.infos.send_Frame(frame2, burst_Number)

            elif identifier == 5:
                if firs == 1:
                    frame = self.infos.generate_Custom_Commit(auth_value, sequence_value, status_value)
                    firs = 0
                message = " commits with body values : "
                self.infos.send_Frame(frame, burst_Number)

            elif identifier == 6:
                if firs == 1:
                    firs = 0
                    frame = self.infos.generate_Custom_Confirm(auth_value, sequence_value, status_value, 0)
                message = " confirms with send-confirm value = 0 ,, with body values : "
                self.infos.send_Frame(frame, burst_Number)


            elif identifier == 7:
                if firs == 1:
                    firs = 0
                    frame = self.infos.generate_Custom_Confirm(auth_value, sequence_value, status_value, 1)
                message = " confirms with send-confirm value = 2 ,, with body values : "
                self.infos.send_Frame(frame, burst_Number)

            if toprint == 1:
                self.logging(auth_value, sequence_value, status_value, message, burst_Number)
                toprint = 0
                print('\n')
        time.sleep(4)
        stopThread = 1
        if self.monitoring_interface == '00':
            if deauth_to_Send_stop == 1:
                print(
                    "\nFound deauthentication frames during the specific attack. Pausing 60 sec before continuing to the next case.")
                time.sleep(60)
                deauth_to_Send_stop = 0
        time.sleep(4)

    def logging(self, auth, seq, stat, message, burst_number):

        string = ("Sending " + str(self.total_frames_to_Send) + message + str(auth) + " " + str(seq) + " " + str(stat))
        if int(self.infos.AP_CHANNEL) > 15:
            string = string + ' ...  5G'
        if burst_number > 1:
            string = string + '... BURSTY'

        print('\n' + string)
        self.state.message = string


class neccessary_Tests:

    def __init__(self, infos):
        self.infos = infos
        self.check_monitor_mode()
        self.check_channel()
        self.search_AP()
        self.check_sae_Exchange()
        time.sleep(3)

    def thread_function(self):
        time.sleep(0.1)

        frame = self.infos.generate_Custom_Confirm(3, 2, 0, 0)
        print("Sending  CONFIRM")
        sendp(frame, iface=self.infos.ATTACKING_INTERFACE, verbose=0)

    def check_sae_Exchange(self):

        print(bcolors.OKGREEN + "\n\nPerforming a SAE exchange: " + bcolors.ENDC)
        frame = self.infos.generate_Custom_Commit(3, 1, 0)
        for i in range(1, 6):
            x = threading.Thread(target=self.thread_function)
            x.start()

            print("Sending  COMMIT")
            answer = srp1(frame, timeout=3, iface=self.infos.ATTACKING_INTERFACE, inter=0.1, verbose=0)
            if answer:
                print("Exchange performed successfully  on " + str(i) + " try\n")
                break
            else:
                print(bcolors.FAIL + "Didnt get answer. " + bcolors.ENDC + " Retrying for " + str(
                    i) + " time. Max tries: 5\n")

    def check_monitor_mode(self):
        mode = 's'

        print(
            bcolors.OKGREEN + "Validating if mode of attacking interface: " + bcolors.ENDC + bcolors.OKBLUE + self.infos.ATTACKING_INTERFACE + bcolors.ENDC + bcolors.OKGREEN + " is set to: " + bcolors.ENDC + bcolors.OKBLUE + "-- MONITOR MODE --" + bcolors.ENDC)
        try:
            mode = subprocess.check_output(['iwconfig ' + self.infos.ATTACKING_INTERFACE + ' | grep Monitor '],
                                           shell=True)
        except subprocess.CalledProcessError as e:
            mode = '1'
        if (len(mode) > 5):
            print(self.infos.ATTACKING_INTERFACE + " IS set to monitor mode. \n\n")
        else:
            print(self.infos.ATTACKING_INTERFACE + " IS NOT set to monitor mode.")
            print("TERMINATING...")
            sys.exit(0)

    def check_channel(self):
        foundd = 0
        print(
            bcolors.OKGREEN + "Validating if channel of: " + bcolors.ENDC + bcolors.OKBLUE + self.infos.ATTACKING_INTERFACE + bcolors.ENDC + bcolors.OKGREEN + " is set to: " + bcolors.ENDC + bcolors.OKBLUE + "-- " + self.infos.AP_CHANNEL + " --" + bcolors.ENDC)
        try:
            channel = subprocess.check_output(
                ['iw ' + self.infos.ATTACKING_INTERFACE + ' info | grep channel | cut -d " " -f2'], shell=True)
        except subprocess.CalledProcessError as e:
            print("iw interface info | grep channel | cut -d " " -f2 returned error")
            channel = '0'
        channel = channel[:-1]
        while True:
            if channel == self.infos.AP_CHANNEL:
                print("Channel of " + self.infos.ATTACKING_INTERFACE + " IS set to: " + self.infos.AP_CHANNEL + '\n\n')
                break;
            else:
                print(
                    "Channel of " + self.infos.ATTACKING_INTERFACE + " IS NOT set to: " + self.infos.AP_CHANNEL + " OR  i cannot correctly retrieve the channel information\n")
                print("You are suggested to manually check and set the interface to the correct channel (if needed)")
                print("If you are sure that the channel is set correctly, INGORE this message.\n\n")
                break;

    def search_AP(self):

        print(
            bcolors.OKGREEN + "Searching for AP in range, with mac address: " + bcolors.ENDC + bcolors.OKBLUE + "--- " + self.infos.AP_MAC + " ---" + bcolors.ENDC)
        print("Searching...")
        sniff(iface=self.infos.ATTACKING_INTERFACE, stop_filter=self.stopfilter, store=0)

    def stopfilter(self, pkt):
        if pkt.haslayer(Dot11):
            dot11_layer = pkt.getlayer(Dot11)

            if isinstance(dot11_layer.addr2, str):
                if dot11_layer.addr2.lower() == self.infos.AP_MAC.lower():
                    print("\nAP found")
                    return True
