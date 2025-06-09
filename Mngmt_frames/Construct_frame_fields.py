import string
import subprocess
from random import choice
from random import randint
from scapy.all import Dot11, Dot11Elt, RadioTap, sendp, hexdump
from time import sleep
import settings
import os
from Logging import LogFiles
from generateBytes import *
from Msgs_colors import bcolors

NUM_OF_FRAMES_TO_SEND = 64

STANDARD_RSN = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'  # RSN Version 1
    '\x00\x0f\xac\x04'  # Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'  # AES Cipher
    '\x00\x0f\xac\x02'  # TKIP Cipher
    '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'  # Pre-Shared Key
    '\x00\x00'))  # RSN Capabilities (no extra capabilities)

STANDARD_TIM = Dot11Elt(ID='TIM', info='\x05\x04\x00\x01\x00\x00')

SUPPORTED_RATES = Dot11Elt(ID='Rates', info='\x82\x84\x8b\x0c\x12\x96\x18\x24')
SUPPL_RATES = Dot11Elt(ID='ESRates', info='\x30\x48\x60\x6c')

STANDARD_HT_CAPABILITIES = Dot11Elt(ID=45, info='\x67\x09\x17\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                                '\x00\x00\x00\x00\x00\x00\x00\x00')
STANDARD_DS = Dot11Elt(ID='DSset', info='\x0b')

STANDARD_EXT_HT_CAPABILITIES = Dot11Elt(ID=127, info='\x00\x00\x08\x00\x00\x00\x00\x40')

STANDARD_POWER_CAPS = Dot11Elt(ID=33, info='\x09\x15')

STANDARD_SUPP_CHANNELS = Dot11Elt(ID=36, info='\x01\x0d')

STANDARD_OVERLAPPING_BSS = Dot11Elt(ID=74, info='\x14\x00\x0a\x00\x2c\x01\xc8\x00\x14\x00\x05\x00\x19')

STANDARD_HT_INFORMATION = Dot11Elt(ID=61, info='\x0b\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                               '\x00\x00\x00\x00\x00')

STANDARD_RM_CAPS = Dot11Elt(ID=70, info='\x31\x08\x01\x00\x00')

STANDARD_MAC_ADDRESS = '00:14:78:53:01:d8'

class Frame:

    def construct_MAC_header(self, subtype, mac_to, mac_from, ap_mac):
        dot11 = Dot11(type=0, subtype=subtype, addr1=mac_to, addr2=mac_from, addr3=ap_mac)
        return RadioTap()/dot11

    def construct_RSN(self, mode):
    # 03 and 14-15 are reserved for PKCS
    # 00 and 14-15 are reserved for AKMS
        rsn_array = [bytearray(b'\x01\x00'),  # RSN Version 1
                     bytearray(b'\x00\x0f\xac'),  # Group Cipher Suite : 00-0f-ac
                     bytearray(b'\x01\x00'),  # Pairwise Cipher Suites (line below)
                     bytearray(b'\x00\x0f\xac'),
                     bytearray(b'\x01\x00'),  # Authentication Key Management Suite (line below)
                     bytearray(b'\x00\x0f\xac'),
                     bytearray(b'')]  # RSN Capabilities
        for item in generate_bytes(1, mode):
            rsn_array[1].append(item)
        for item in generate_bytes(1, mode):
            rsn_array[3].append(item)
        for item in generate_bytes(1, mode):
            rsn_array[5].append(item)
        for item in generate_bytes(2, mode):
            rsn_array[6].append(item)
        rsn_bytes = b''.join(rsn_array)
        return Dot11Elt(ID='RSNinfo', info=rsn_bytes, len=len(rsn_bytes))

    def construct_TIM(self, mode):
        tim_bytes = bytearray(b'')
        for item in generate_bytes(6, mode):
            tim_bytes.append(item)
        return Dot11Elt(ID='TIM', info=tim_bytes)

    def generate_MAC(self):
        mac_bytes = generate_bytes(6, 'standard')
        return '%02x:%02x:%02x:%02x:%02x:%02x' % (mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3],
                                              mac_bytes[4], mac_bytes[5])

    def generate_SSID(self, mode):
        ssid = bytearray(b'')
        for item in generate_bytes(16, mode):
            ssid.append(item)
        return Dot11Elt(ID='SSID', info=ssid, len=len(ssid))

    def generate_supp_speed(self, mode):
        # the standard speed rates is \x82\x84\x8b\x0c\x12\x96\x18\x24, the fields consists of 8 octets
        supported_rates = bytearray(b'')
        # standard supp rates are \x30\x48\60\x6c
        extended_supported_rates = bytearray(b'')
        for item in generate_bytes(8, mode):
            supported_rates.append(item)
        for item in generate_bytes(4, mode):
            extended_supported_rates.append(item)
        rates = Dot11Elt(ID='Rates', info=supported_rates, len=len(supported_rates)) \
        / Dot11Elt(ID='ESRates', info=extended_supported_rates, len=len(extended_supported_rates))
        return rates

    def generate_channel_use(self, mode):
        # 2.412 to 2.472 --> channels 1-13 and 14 is Channel Center Frequency
        # 5.170 to 5.825 --> 4 sub bands (U-NII bands) in use
        # U-NII-1 most used band --> channels 34-48 incr by 2 (freqs. 5170–5240)
        # U-NII-2a --> channels 52-64 incr by 4 (freqs. 5260–5320)
        # U-NII-2b --> is unsed (freqs. 5350–5470)
        # U-NII-2c --> channels 100-140 incr by 4 (freqs. 5500–5700)
        # U-NII-3 (not available worldwide) --> 149-161 incr by 4 (freqs. 5745–5825)
        # (freqs. 5845–5925) future
        # not all U-NII bands are available worldwide
        channel = bytearray(b'')
        for item in generate_bytes(1, mode):
            channel.append(item)
        return Dot11Elt(ID='DSset', info=channel, len=len(channel))

    def generate_HT_capabilities(self, mode):
        ht_cap = bytearray(b'')
        for item in generate_bytes(26, mode):
            ht_cap.append(item)
        return Dot11Elt(ID=45, info=ht_cap, len=len(ht_cap))

    def generate_extended_HT_capabilities(self, mode):
        ext_ht_cap = bytearray(b'')
        for item in generate_bytes(8, mode):
            ext_ht_cap.append(item)
        return Dot11Elt(ID=127, info=ext_ht_cap, len=len(ext_ht_cap))

    def generate_power_capability(self, mode):
        power_cap = bytearray(b'')
        for item in generate_bytes(2, mode):
            power_cap.append(item)
        return Dot11Elt(ID=33, info=power_cap, len=len(power_cap))

    def generate_supported_channels(self, mode):
        supp_ch = bytearray(b'')
        for item in generate_bytes(2, mode):
            supp_ch.append(item)
        return Dot11Elt(ID=36, info=supp_ch, len=len(supp_ch))

    def generate_overlapping_BSS(self, mode):
        overl_bss = bytearray(b'')
        for item in generate_bytes(14, mode):
            overl_bss.append(item)
        return Dot11Elt(ID=74, info=overl_bss, len=len(overl_bss))

    def generate_HT_information(self, mode):
        ht_info = bytearray(b'')
        for item in generate_bytes(22, mode):
            ht_info.append(item)
        return Dot11Elt(ID=61, info=ht_info, len=len(ht_info))

    def generate_RM_enabled_capabilities(self, mode):
        rm_caps = bytearray(b'')
        for item in generate_bytes(5, mode):
            rm_caps.append(item)
        return Dot11Elt(ID=70, info=rm_caps, len=len(rm_caps))

    def send_Frame(self, frame, interface):
        sendp(frame, count=2, iface=interface, verbose=0)
        
    def check_conn_aliveness(self, frame, fuzzing_stage=0):
        
        def check_conn():
            sleep(2)
            while settings.conn_loss or not settings.is_alive:
                pass
            return
        
        if not settings.is_alive:
            if fuzzing_stage == 0:
                pass
            else:
                self.fuzzer_state[fuzzing_stage]["conn_loss"] = True
            print('\nHexDump of frame:')
            hexdump(frame)
            check_conn()
            return True
        elif settings.conn_loss:
            if fuzzing_stage == 0:
                pass
            else:
                self.fuzzer_state[fuzzing_stage]["conn_loss"] = True
            print('\nHexDump of frame:')
            hexdump(frame)
            input(f'\n{bcolors.FAIL}Deauth or Disass frame found.{bcolors.ENDC}\n\n{bcolors.WARNING}Reconnect, if needed, and press Enter to resume:{bcolors.ENDC}\n')
            print(f"{bcolors.OKCYAN}Pausing for 20'' and proceeding to the next subtype of frames{bcolors.ENDC}\n")
            sleep(20)
            settings.is_alive = True
            settings.conn_loss = False
            check_conn()
            return True
        return False
        
    def fuzz(self, mode, list_of_fields, interface, is_auth_frame=False):
            
        init_logs = LogFiles()
        counter = 1
        frames_till_disr = []
        caused_disc = [(999, 999, 999)]
        if mode == 'standard' or mode == 'random':
            subprocess.call(['clear'], shell=True)
            print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ')
            print('You selected mode:', mode)
            while True:
                frames_till_disr = []
                subprocess.call(['echo' + f' Fuzzing cycle No.{counter}\n'], shell=True)
                subprocess.call(['echo' + f' {bcolors.OKGREEN}Stop the fuzzing and monitoring processes with 2 consecutive Ctrl+c{bcolors.ENDC}\n'], shell=True)
                print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
                for i in list_of_fields:
                    if list_of_fields[i]["conn_loss"] == True:
                        continue
                    if is_auth_frame and mode == 'standard':
                        caused_disc = self.fuzz_for_allowed_values(caused_disc)
                        break
                    if i == 'empty':
                        subprocess.call(
                            ['echo' + f' Transmitting {2*NUM_OF_FRAMES_TO_SEND} {i} {bcolors.OKBLUE}{self.frame_name}{bcolors.ENDC} frames'], shell=True)
                        for _ in range(1, NUM_OF_FRAMES_TO_SEND):
                            frame = list_of_fields[i]["send_function"](mode)
                            frames_till_disr += frame
                            if(self.check_conn_aliveness(frame, i)):
                                init_logs.logging_conn_loss(f"Connectivity issues detected while sending {i} {self.frame_name} frames\nframe = {frame}\n\n", init_logs.is_alive_path_mngmt)
                                init_logs.logging_conn_loss(f"Prior to connection loss found the above frames were sent. Timestamp of logging is cycle {counter}\n", init_logs.frames_till_disr_mngmt)
                                for item in frames_till_disr:
                                    init_logs.logging_conn_loss(f"\nframe = {item}\n\n", init_logs.frames_till_disr_mngmt)
                                init_logs.logging_conn_loss(f"*----Frames pattern above----*\n", init_logs.frames_till_disr_mngmt)
                                frames_till_disr = []
                                break
                            else:
                                self.send_Frame(frame, interface)
                    elif i == "addresses reversed '(destination = AP, source = STA)'" and mode == 'standard':
                        pass
                    elif i == "allowed" and mode == 'random':
                        pass
                    else:
                        subprocess.call(
                            ['echo' + f' Transmitting {2*NUM_OF_FRAMES_TO_SEND} {bcolors.OKBLUE}{self.frame_name}{bcolors.ENDC} frames with random {i}'], shell=True)
                        for _ in range(1, NUM_OF_FRAMES_TO_SEND):
                            frame = list_of_fields[i]["send_function"](mode)
                            frames_till_disr += frame
                            if(self.check_conn_aliveness(frame, i)):
                                init_logs.logging_conn_loss(f"Connectivity issues detected while sending {self.frame_name} frames with malformed {i}\nframe = {frame}\n\n", init_logs.is_alive_path_mngmt)
                                init_logs.logging_conn_loss(f"Prior to connection loss found the above frames were sent. Timestamp of logging is cycle {counter}\n", init_logs.frames_till_disr_mngmt)
                                for item in frames_till_disr:
                                    init_logs.logging_conn_loss(f"\nframe = {item}\n\n", init_logs.frames_till_disr_mngmt)
                                init_logs.logging_conn_loss(f"*----Frames pattern above----*\n", init_logs.frames_till_disr_mngmt)
                                frames_till_disr = []
                                break
                            else:
                                self.send_Frame(frame, interface)
                subprocess.call(['clear'], shell=True)
                counter += 1
