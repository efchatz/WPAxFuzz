from Mngmt_frames.Construct_frame_fields import bcolors
from scapy.all import Dot11, RadioTap, sendp, hexdump
import subprocess
import os
from time import sleep
from random import randint
import settings
from Logging import LogFiles
from generateBytes import *
import binascii

NUM_OF_BATCHES = 4
FRAME_NAMES = ['Beamforming Report Poll', 'VHT/HE NDP Announcement', 'Control Frame Extension', 'Control wrapper', 'Block Ack Request (BAR)', 'Block Ack', 'PS-Poll (Power Save-Poll)', 'RTS–Request to Send', 'CTS-Clear to Send', 'ACK', 'CF-End (Contention Free-End)', 'CF-End & CF-ACK']

class ControlFrames:

    def __init__(self, dest_addr, source_addr, interface):
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface

    def generate_MAC_header(self, frame_id, flag_byte):
        dot11 = Dot11(type=1, subtype=frame_id, FCfield=flag_byte, addr1=self.dest_addr, addr2=self.source_addr)
        MAC_header = RadioTap() / dot11
        return MAC_header
        
    def generate_random_payload(self, frame_id, flag_byte, multiplier):
        MAC_header = self.generate_MAC_header(frame_id, flag_byte)
        
        def payload_portion(num_of_bytes):
            payload = bytearray(b'')
            for item in generate_bytes(num_of_bytes, 'standard'):
                payload.append(item)
            return bytes(payload)
        
        
        if multiplier == 1:
            if frame_id in {4,5,6}:
                return MAC_header / binascii.unhexlify(self.source_addr.replace(':', '')) / payload_portion(26)
            else:
                return MAC_header / payload_portion(32)
        elif multiplier == 2:
            if frame_id in {4,5,6}:
                return MAC_header / binascii.unhexlify(self.source_addr.replace(':', '')) / payload_portion(26) / payload_portion(32)
            else:
                return MAC_header / payload_portion(32) / payload_portion(32)
        elif multiplier == 3:
            if frame_id in {4,5,6}:
                return MAC_header / binascii.unhexlify(self.source_addr.replace(':', '')) / payload_portion(26) / payload_portion(32) / payload_portion(32) / payload_portion(32)
            else:
                return MAC_header / payload_portion(32) / payload_portion(32) / payload_portion(32) / payload_portion(32)
        elif multiplier == 4:
            if frame_id in {4,5,6}:
                return MAC_header / binascii.unhexlify(self.source_addr.replace(':', '')) / payload_portion(26) / payload_portion(32) / payload_portion(32) / payload_portion(32) / payload_portion(32) / payload_portion(32) / payload_portion(32) / payload_portion(32)
            else:
                return MAC_header / payload_portion(32) / payload_portion(32) / payload_portion(32) / payload_portion(32) / payload_portion(32) / payload_portion(32) / payload_portion(32) / payload_portion(32)
            
    def print_message(self, fuzz_stage):
        subprocess.call(['clear'], shell=True)
        print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ')
        subprocess.call(['echo' + f' Fuzzing with Control Frames: Testing {fuzz_stage}\n'], shell=True)
        subprocess.call(['echo' + f' {bcolors.OKGREEN}Fuzzing process will exit automatically{bcolors.ENDC}\n'], shell=True)
        print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
        
    def check_conn_aliveness(self, frame):
        
        def check_conn():
            sleep(2)
            while settings.conn_loss or not settings.is_alive:
                pass
            return
        
        if not settings.is_alive:
            print('\nHexDump of frame:')
            hexdump(frame)
            check_conn()
            return True
        elif settings.conn_loss:
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
        
    def fuzz_ctrl_frames(self):
        init_logs = LogFiles()
        self.print_message(f" {bcolors.OKBLUE}Frame Control Flags{bcolors.ENDC}")    
        for frame_id in range(4, 16):
            print(f'Sending {bcolors.OKBLUE}{FRAME_NAMES[frame_id-16]}{bcolors.ENDC} frames with Frame Control Flags checked within the range (0,256)')
            for flag_byte in range (0, 256):
                frame = self.generate_MAC_header(frame_id, flag_byte)
                if self.check_conn_aliveness(frame):
                    init_logs.logging_conn_loss(f"Connectivity issues detected while sending {FRAME_NAMES[frame_id-16]} frames with Frame Control Flags equal to {flag_byte}\nframe = {frame}\n\n", init_logs.is_alive_path_ctrl)
                    break
                else:
                    sendp(frame, count=128, iface=self.interface, verbose=0)
                if frame_id == 6 and flag_byte == 11:
                     break
        subprocess.call(['clear'], shell=True)       
        self.print_message(f" {bcolors.OKBLUE}Payload overflow{bcolors.ENDC}")
        for frame_id in range(4, 16):
            print(f'Sending {bcolors.OKBLUE}{FRAME_NAMES[frame_id-16]}{bcolors.ENDC} frames with random payload multiplied in range (1,4)')
            for multiplier in range(1, 5):
                for _ in range(0, NUM_OF_BATCHES):
                    frame = self.generate_random_payload(frame_id, randint(0,257), multiplier)
                    if self.check_conn_aliveness(frame):
                        init_logs.logging_conn_loss(f"Connectivity issues detected while sending {FRAME_NAMES[frame_id-16]} frames with payload size equal to {multiplier*32} bytes\nframe = {frame}\n\n", init_logs.is_alive_path_ctrl)
                        break
                    else:
                        sendp(frame, count=128, iface=self.interface, verbose=0)
                else: #for-else to break nested loop
                    continue
                break
        subprocess.call(['clear'], shell=True)
        self.print_message(f" {bcolors.OKBLUE}Frame Control Flags + Payload overflow{bcolors.ENDC}")
        for frame_id in range(4, 16):
            print(f'Sending {bcolors.OKBLUE}{FRAME_NAMES[frame_id-16]}{bcolors.ENDC} frames with Frame Control Flags checked within the range (0,256) and with random payload multiplied in range (1,4)')
            for flag_byte in range (0, 256):
                for multiplier in range(1, 5):
                    frame = self.generate_random_payload(frame_id, flag_byte, multiplier)
                    if self.check_conn_aliveness(frame):
                        init_logs.logging_conn_loss(f"Connectivity issues detected while sending {FRAME_NAMES[frame_id-16]} frames with Frame Control Flags equal to {flag_byte} and payload size equal to {multiplier*32} bytes\nframe = {frame}\n\n", init_logs.is_alive_path_ctrl)
                        break
                    else:
                        sendp(frame, count=128, iface=self.interface, verbose=0)
                    if frame_id == 6 and flag_byte == 11:
                        break
                else: #for-else to break nested loop
                    continue
                break
        print(f'{bcolors.FAIL}Exiting Fuzzer!!{bcolors.ENDC}')
