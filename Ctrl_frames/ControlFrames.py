from Msgs_colors import bcolors
from scapy.all import Dot11, RadioTap, sendp, hexdump
import subprocess
import os
from time import sleep
from random import randint
import settings
from Logging import LogFiles
from generateBytes import generate_bytes
import binascii
from threading import Thread

NUM_OF_FRAMES_TO_SEND = 64

class ControlFrames:

    def __init__(self, dest_addr, source_addr, interface, mode, frame_id, ctrl_frm_ext):
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.mode = mode
        self.frame_id = frame_id
        self.ctrl_frm_ext = ctrl_frm_ext
        self.rotating_sym = Thread(target=self.rotating_symbol)
        self.ctrl_subtypes = [
               {
                "frame_id": 4,
                "frame_name": "Beamforming Report Poll",
                "payload_size": 1,
                "standard_payload": binascii.unhexlify(self.source_addr.replace(':', '')) + b'\xfd',
                },
               {
                 "frame_id": 5,
                "frame_name": "VHT/HE NDP Announcement",
                "payload_size": 5,
                "standard_payload": binascii.unhexlify(self.source_addr.replace(':', '')) + b'\xd3\x57\x68\xf1\x33',
                },
               {
                "frame_id": 6,
                "ctrl_ext_turn": 2,
                "frame_name": "Poll",
                "payload_size": 2,
                },
               {
                "frame_id": 6,
                "ctrl_ext_turn": 3,
                "frame_name": "Service period request",
                "payload_size": 7,
                },
               {
                "frame_id": 6,
                "ctrl_ext_turn": 4,
                "frame_name": "Grant",
                "payload_size": 7,
                },
               {
                "frame_id": 6,
                "ctrl_ext_turn": 5,
                "frame_name": "DMG CTS",
                "payload_size": 0,
                },
               {
                "frame_id": 6,
                "ctrl_ext_turn": 6,
                "frame_name": "DMG DTS",
                "payload_size": 6,
                },
               {
                "frame_id": 6,
                "ctrl_ext_turn": 7,
                "frame_name": "Grant Ack",
                "payload_size": 7,
                },
               {
                "frame_id": 6,
                "ctrl_ext_turn": 8,
                "frame_name": "Sector sweep (SSW)",
                "payload_size": 6,
                },
               {
                "frame_id": 6,
                "ctrl_ext_turn": 9,
                "frame_name": "Sector sweep feedback (SSW-Feedback)",
                "payload_size": 8,
                },
               {
                "frame_id": 6,
                "ctrl_ext_turn": 10,
                "frame_name": "Sector sweep Ack (SSW-Ack)",
                "payload_size": 8,
                },
               {
                "frame_id": 7,
                "frame_name": "Control wrapper",
                "payload_size": 28,
                "standard_payload": b'\x03\x22\x65\x87\x32\xaa\xed\x43\x11\x00\xe1\x55\x01\xd1\xff\x91\x85\x39\x45\xe1\xe1\x23\x78\xdd\xda\xad\xe8\x93',
                },
               {
                "frame_id": 8,
                "frame_name": "Block Ack Request (BAR)",
                "payload_size": 12,
                "standard_payload": b'\x00\x05\x97\x30\x00\x00\x00\x00\x00\x00\x00\x00',
                },
               {
                "frame_id": 9,
                "frame_name": "Block Ack",
                "payload_size": 12,
                "standard_payload": b'\x60\x05\x03\x50\x00\x00\x00\x00\x00\x00\x00\x00'
                },
               {
                "frame_id": 10,
                "frame_name": "PS-Poll (Power Save-Poll)",
                "payload_size": 0,
                "standard_payload": b'',
                },
               {
                "frame_id": 11,
                "frame_name": "RTS–Request to Send",
                "payload_size": 0,
                "standard_payload": b'',
                },
               {
                "frame_id": 12,
                "frame_name": "CTS-Clear to Send",
                "payload_size": 0,
                "standard_payload": b'',
                },
               {
                "frame_id": 13,
                "frame_name": "ACK",
                "payload_size": 0,
                "standard_payload": b'',
                },
               {
                "frame_id": 14,
                "frame_name": "CF-End (Contention Free-End)",
                "payload_size": 0,
                "standard_payload": b'',
                },
               {
                "frame_id": 15,
                "frame_name": "CF-End & CF-ACK",
                "payload_size": 0,
                "standard_payload": b'',
                }
        ]
        self.fuzzer_state = {
            "Frame Control Flags": {
                "send_function": self.generate_frame_with_random_FCf,
                "conn_loss": False
                },
            "payload": {
                "send_function": self.generate_frame_with_random_payload,
                "conn_loss": False
                },
            "Frame Control Flags + payload": {
                "send_function": self.generate_frame_with_random_FCf_and_payload,
                "conn_loss": False
                },
        }
        
    def rotating_symbol(self):
        subprocess.call(['./Ctrl_frames/rot.sh'])
        
    def extract_frame_info(self):
        for frame_type in self.ctrl_subtypes:
            if self.frame_id + 3 == frame_type["frame_id"]:
                if frame_type["frame_id"] == 6:
                    if frame_type["ctrl_ext_turn"] == self.ctrl_frm_ext:
                        return frame_type
                else:
                    return frame_type
        
    def construct_bytes(self, num_of_bytes):
        payload = bytearray(b'')
        for item in generate_bytes(num_of_bytes, self.mode):
            payload.append(item)
        return bytes(payload)
        
    def generate_MAC_header(self, FCf=0):
        dot11 = Dot11(type=1, subtype=self.frame_id+3, FCfield=FCf, addr1=self.dest_addr, addr2=self.source_addr)
        MAC_header = RadioTap() / dot11
        return MAC_header
        
    def generate_random_payload(self):
        frame_info = self.extract_frame_info()
        if self.mode == 'standard':
            if frame_info['payload_size'] != 0:
                if self.frame_id + 3 in {4,5,6}:
                    if self.frame_id + 3 == 6:
                        if self.ctrl_frm_ext == 5:
                            return binascii.unhexlify(self.source_addr.replace(':', ''))
                        else:
                            return binascii.unhexlify(self.source_addr.replace(':', '')) + self.construct_bytes(frame_info['payload_size'])
                    else:
                        return binascii.unhexlify(self.source_addr.replace(':', '')) + self.construct_bytes(frame_info['payload_size'])
                else:
                    return self.construct_bytes(frame_info['payload_size'])
            else:
                if self.frame_id + 3 in {4,5,6}:
                    return binascii.unhexlify(self.source_addr.replace(':', ''))
                else:
                    return b''
        elif self.mode == 'random':
            if self.frame_id + 3 in {4,5,6}:
                return binascii.unhexlify(self.source_addr.replace(':', '')) + self.construct_bytes(frame_info['payload_size'])
            else:
                return self.construct_bytes(frame_info['payload_size'])

    def generate_frame_with_random_FCf(self):
        frame_info = self.extract_frame_info()
        return self.generate_MAC_header(int.from_bytes(self.construct_bytes(1), "big")) / frame_info["standard_payload"]
        
    def generate_frame_with_random_payload(self, FCf=0):
        MAC_header = self.generate_MAC_header(FCf)
        payload = self.generate_random_payload()
        return MAC_header / payload
        
            
    def generate_frame_with_random_FCf_and_payload(self):
        MAC_header = self.generate_MAC_header(int.from_bytes(self.construct_bytes(1), "big"))
        payload = self.generate_random_payload()
        return MAC_header / payload
      
    def check_conn_aliveness(self, frame, fuzzing_stage):
        
        def check_conn():
            sleep(2)
            while settings.conn_loss or not settings.is_alive:
                pass
            return
        
        if not settings.is_alive:
            self.fuzzer_state[fuzzing_stage]["conn_loss"] = True
            print('\nHexDump of frame:')
            hexdump(frame)
            check_conn()
            return True
        elif settings.conn_loss:
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
        
    def fuzz_ctrl_frames(self):
        frames_till_disr = []
        counter = 1
        init_logs = LogFiles()
        if self.mode == 'standard' or self.mode == 'random':
            subprocess.call(['clear'], shell=True)
            print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ')
            print('You selected mode:', self.mode)
            while True:
                frames_till_disr = []
                subprocess.call(['echo' + f' Fuzzing cycle No.{counter}\n'], shell=True)
                subprocess.call(['echo' + f' {bcolors.OKGREEN}Stop the fuzzing and monitoring processes with 2 consecutive Ctrl+c{bcolors.ENDC}\n'], shell=True)
                print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
                frame_info = self.extract_frame_info()
                for i in self.fuzzer_state:
                    if self.fuzzer_state[i]["conn_loss"] == True:
                        continue
                    if frame_info["frame_id"] == 6:
                        subprocess.call(['clear'], shell=True)
                        print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ')
                        print('You selected mode:', self.mode)
                        subprocess.call(['echo' + f' {bcolors.OKGREEN}Stop the fuzzing and monitoring processes with 2 consecutive Ctrl+c{bcolors.ENDC}\n'], shell=True)
                        print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
                        print(f'Transmitting {bcolors.OKBLUE}{frame_info["frame_name"]}{bcolors.ENDC} frames with random payload')
                        self.rotating_sym.start()
                        print('\n')
                        while True:
                            frame =  self.fuzzer_state["payload"]["send_function"](self.ctrl_frm_ext)
                            frames_till_disr += frame
                            if(self.check_conn_aliveness(frame, i)):
                                init_logs.logging_conn_loss(f"Connectivity issues detected while sending {frame_info['frame_name']} frames with random {i}\nframe = {frame}\n\n", init_logs.is_alive_path_ctrl)
                                init_logs.logging_conn_loss(f"Prior to connection loss found the above frames were sent. Timestamp of logging is cycle {counter}\n", init_logs.frames_till_disr_ctrl)
                                for item in frames_till_disr:
                                    init_logs.logging_conn_loss(f"\nframe = {item}\n\n", init_logs.frames_till_disr_ctrl)
                                init_logs.logging_conn_loss(f"*----Frames pattern above----*\n", init_logs.frames_till_disr_ctrl)
                                frames_till_disr = []
                                break
                            else:
                                sendp(frame, count=2, iface=self.interface, verbose=0)
                    elif frame_info["payload_size"] == 0 and self.mode == 'standard':
                        subprocess.call(['clear'], shell=True)
                        print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ')
                        print('You selected mode:', self.mode)
                        subprocess.call(['echo' + f' {bcolors.OKGREEN}Stop the fuzzing and monitoring processes with 2 consecutive Ctrl+c{bcolors.ENDC}\n'], shell=True)
                        print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
                        print(f'Transmitting {bcolors.OKBLUE}{frame_info["frame_name"]}{bcolors.ENDC} frames with random Frame Control Flags')
                        self.rotating_sym.start()
                        print('\n')
                        while True:
                            frame =  self.fuzzer_state["Frame Control Flags"]["send_function"]()
                            frames_till_disr += frame
                            if(self.check_conn_aliveness(frame, i)):
                                init_logs.logging_conn_loss(f"Connectivity issues detected while sending {frame_info['frame_name']} frames with random {i}\nframe = {frame}\n\n", init_logs.is_alive_path_ctrl)
                                init_logs.logging_conn_loss(f"Prior to connection loss found the above frames were sent. Timestamp of logging is cycle {counter}\n", init_logs.frames_till_disr_ctrl)
                                for item in frames_till_disr:
                                    init_logs.logging_conn_loss(f"\nframe = {item}\n\n", init_logs.frames_till_disr_ctrl)
                                init_logs.logging_conn_loss(f"*----Frames pattern above----*\n", init_logs.frames_till_disr_ctrl)
                                frames_till_disr = []
                                break
                            else:
                                sendp(frame, count=2, iface=self.interface, verbose=0)
                    else:   
                        print(f'Transmitting {bcolors.OKBLUE}{frame_info["frame_name"]}{bcolors.ENDC} frames with random {i}')
                        for _ in range(1, NUM_OF_FRAMES_TO_SEND):
                            frame =  self.fuzzer_state[i]["send_function"]()
                            frames_till_disr += frame
                            if(self.check_conn_aliveness(frame, i)):
                                init_logs.logging_conn_loss(f"Connectivity issues detected while sending {frame_info['frame_name']} frames with random {i}\nframe = {frame}\n\n", init_logs.is_alive_path_ctrl)
                                init_logs.logging_conn_loss(f"Prior to connection loss found the above frames were sent. Timestamp of logging is cycle {counter}\n", init_logs.frames_till_disr_ctrl)
                                for item in frames_till_disr:
                                    init_logs.logging_conn_loss(f"\nframe = {item}\n\n", init_logs.frames_till_disr_ctrl)
                                init_logs.logging_conn_loss(f"*----Frames pattern above----*\n", init_logs.frames_till_disr_ctrl)
                                frames_till_disr = []
                                break
                            else:
                                sendp(frame, count=2, iface=self.interface, verbose=0)
                subprocess.call(['clear'], shell=True)
                counter += 1
