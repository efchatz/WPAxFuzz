from Msgs_colors import bcolors
from scapy.all import Dot11, RadioTap, sendp, hexdump
import subprocess
import os
from time import sleep
import settings
from Logging import LogFiles
from fuzz import fuzzer
from generateBytes import generate_bytes
from threading import Thread

NUM_OF_FRAMES_TO_SEND = 64

class DataFrames:
    
    def __init__(self, dest_addr, source_addr, interface, mode, frame_id, is_STA_the_target):
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.mode = mode
        self.frame_id = frame_id
        self.is_STA_the_target = is_STA_the_target
        self.rotating_sym = Thread(target=self.rotating_symbol)
        self.data_subtypes = [
            {
                "frame_id": 0,
                "frame_name": "Data",
                "payload_size": 36,
                "standard_payload": b'\x04\x00\x74\x49\xff\x11\xff\xac\xbc\xff\x2a\xeb\xff\xff\xff\x23\xbe\xca\xac\xff\xff\x11\xff\x22\xff\xff\xff\x12\x54\xff\xbb\xed\x7f\x92\x08\x80',
            },
            {
                "frame_id": 1,
                "frame_name": "Data + CF-ACK",
                "payload_size": 32,
                "standard_payload": b'\x01\xd1\xff\x91\x85\x39\x45\xe1\xe1\x23\x78\xdd\xda\xad\xe8\x93\x03\x22\x65\x87\x32\xaa\xed\x43\x11\x00\xe1\x55\x01\xd1\xff\x91',
            },
            {
                "frame_id": 2,
                "frame_name": "Data + CF-Poll",
                "payload_size": 32,
                "standard_payload": b'\x01\xd1\xff\x91\x85\x39\x45\xe1\xe1\x23\x78\xdd\xda\xad\xe8\x93\x03\x22\x65\x87\x32\xaa\xed\x43\x11\x00\xe1\x55\x01\xd1\xff\x91',
            },
            {
                "frame_id": 3,
                "frame_name": "Data + CF-Ack + CF-Poll",
                "payload_size": 32,
                "standard_payload": b'\x01\xd1\xff\x91\x85\x39\x45\xe1\xe1\x23\x78\xdd\xda\xad\xe8\x93\x03\x22\x65\x87\x32\xaa\xed\x43\x11\x00\xe1\x55\x01\xd1\xff\x91',
            },
            {
                "frame_id": 4,
                "frame_name": "Null Data",
                "payload_size": 0,
                "standard_payload": b'',
            },
            {
                "frame_id": 5,
                "frame_name": "CF-ACK (no data)",
                "payload_size": 0,
                "standard_payload": b'',
            },
            {
                "frame_id": 6,
                "frame_name": "CF-Poll (no data)",
                "payload_size": 0,
                "standard_payload": b'',
            },
            {
                "frame_id": 7,
                "frame_name": "CF-ACK + CF-Poll (no data)",
                "payload_size": 0,
                "standard_payload": b'',
            },
            {
                "frame_id": 8,
                "frame_name": "QoS Data",
                "payload_size": 32,
                "standard_payload": b'\x01\xd1\xff\x91\x85\x39\x45\xe1\xe1\x23\x78\xdd\xda\xad\xe8\x93\x03\x22\x65\x87\x32\xaa\xed\x43\x11\x00\xe1\x55\x01\xd1\xff\x91',
            },
            {
                "frame_id": 9,
                "frame_name": "QoS Data + CF-ACK",
                "payload_size": 32,
                "standard_payload": b'\x01\xd1\xff\x91\x85\x39\x45\xe1\xe1\x23\x78\xdd\xda\xad\xe8\x93\x03\x22\x65\x87\x32\xaa\xed\x43\x11\x00\xe1\x55\x01\xd1\xff\x91',
            },
            {
                "frame_id": 10,
                "frame_name": "QoS Data + CF-Poll",
                "payload_size": 32,
                "standard_payload": b'\x01\xd1\xff\x91\x85\x39\x45\xe1\xe1\x23\x78\xdd\xda\xad\xe8\x93\x03\x22\x65\x87\x32\xaa\xed\x43\x11\x00\xe1\x55\x01\xd1\xff\x91',
            },
            {
                "frame_id": 11,
                "frame_name": "QoS Data + CF-ACK + CF-Poll",
                "payload_size": 32,
                "standard_payload": b'\x01\xd1\xff\x91\x85\x39\x45\xe1\xe1\x23\x78\xdd\xda\xad\xe8\x93\x03\x22\x65\x87\x32\xaa\xed\x43\x11\x00\xe1\x55\x01\xd1\xff\x91',
            },
            {
                "frame_id": 12,
                "frame_name": "QoS Null Data",
                "payload_size": 2,
                "standard_payload": b'\x00\x06',
            },
            {
                "frame_id": 13,
                "frame_name": "Reserved Data Frame",
                "payload_size": 0,
                "standard_payload": b'',
            },
            {
                "frame_id": 14,
                "frame_name": "QoS Data + CF-Poll (no data)",
                "payload_size": 6,
                "standard_payload": b'\x04\x00\x74\x49\xff\x11',
            },
            {
                "frame_id": 15,
                "frame_name": "QoS CF-ACK + CF-Poll (no data)",
                "payload_size": 6,
                "standard_payload": b'\x04\x00\x74\x49\xff\x11',
            }
        ]
        self.fuzzer_state = {
            "Frame Control Flags": {
                "send_function": self.generate_frame_with_random_FCf,
                "conn_loss": False
                },
            "Sequence number": {
                "send_function": self.generate_frame_with_random_SC,
                "conn_loss": False
                },
            "payload": {
                "send_function": self.generate_frame_with_random_payload,
                "conn_loss": False
                },
            "Frame Control Flags + Sequence number + payload": {
                "send_function": self.generate_frame_with_random_FCf_SC_and_payload,
                "conn_loss": False
                },
        }
    
    def rotating_symbol(self):
        subprocess.call(['./Data_frames/rot.sh'])
    
    def extract_frame_info(self):
        for frame_type in self.data_subtypes:
            if self.frame_id - 1 == frame_type["frame_id"]:
                return frame_type
        
        
    def construct_bytes(self, num_of_bytes):
        payload = bytearray(b'')
        for item in generate_bytes(num_of_bytes, fuzzer, self.mode):
            payload.append(item)
        return bytes(payload)
        
    def generate_MAC_header(self, FCf=11, seq_num=int.from_bytes(b'\x00\x00', "big")):
        if self.is_STA_the_target:
            dot11 = Dot11(type=2, subtype=self.frame_id-1, FCfield=FCf, addr1=self.dest_addr, addr2=self.source_addr, addr3=self.source_addr, SC=seq_num, addr4=self.source_addr)
        else:
            dot11 = Dot11(type=2, subtype=self.frame_id-1, FCfield=FCf, addr1=self.dest_addr, addr2=self.source_addr, addr3=self.dest_addr, SC=seq_num, addr4=self.source_addr)
        MAC_header = RadioTap() / dot11
        return MAC_header
        
    def generate_random_payload(self):
        frame_info = self.extract_frame_info()
        if frame_info['payload_size'] == 0:
            return b''
        else:
            return self.construct_bytes(frame_info['payload_size'])
            
    def generate_frame_with_random_SC(self):
        frame_info = self.extract_frame_info()
        while True:
            SC = int.from_bytes(self.construct_bytes(2), "big")
            if SC < 65535:
                return self.generate_MAC_header(0, SC) / frame_info["standard_payload"]
        
        
    def generate_frame_with_random_FCf(self):
        frame_info = self.extract_frame_info()
        return self.generate_MAC_header(int.from_bytes(self.construct_bytes(1), "big")) / frame_info["standard_payload"]
        
    def generate_frame_with_random_payload(self, FCf=11):
        MAC_header = self.generate_MAC_header(FCf)
        payload = self.generate_random_payload()
        return MAC_header / payload
    
    def generate_frame_with_random_FCf_SC_and_payload(self):
        while True:
            SC = int.from_bytes(self.construct_bytes(2), "big")
            if SC < 65535:
                MAC_header = self.generate_MAC_header(int.from_bytes(self.construct_bytes(1), "big"), SC)
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
        
    def fuzz_data_frames(self):
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
                    if frame_info["payload_size"] == 0 and self.mode == 'standard':
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
                                init_logs.logging_conn_loss(f"Connectivity issues detected while sending {frame_info['frame_name']} frames with random {i}\nframe = {frame}\n\n", init_logs.is_alive_path_data)
                                init_logs.logging_conn_loss(f"Prior to connection loss found the above frames were sent. Timestamp of logging is cycle {counter}\n", init_logs.frames_till_disr_data)
                                for item in frames_till_disr:
                                    init_logs.logging_conn_loss(f"\nframe = {item}\n\n", init_logs.frames_till_disr_data)
                                init_logs.logging_conn_loss(f"*----Frames pattern above----*\n", init_logs.frames_till_disr_data)
                                frames_till_disr = []
                                break
                            else:
                                sendp(frame, count=16, iface=self.interface, verbose=0)
                    else:   
                        print(f'Transmitting {bcolors.OKBLUE}{frame_info["frame_name"]}{bcolors.ENDC} frames with random {i}')
                        for _ in range(1, NUM_OF_FRAMES_TO_SEND):
                            frame =  self.fuzzer_state[i]["send_function"]()
                            frames_till_disr += frame
                            if(self.check_conn_aliveness(frame, i)):
                                init_logs.logging_conn_loss(f"Connectivity issues detected while sending {frame_info['frame_name']} frames with random {i}\nframe = {frame}\n\n", init_logs.is_alive_path_data)
                                init_logs.logging_conn_loss(f"Prior to connection loss found the above frames were sent. Timestamp of logging is cycle {counter}\n", init_logs.frames_till_disr_data)
                                for item in frames_till_disr:
                                    init_logs.logging_conn_loss(f"\nframe = {item}\n\n", init_logs.frames_till_disr_data)
                                init_logs.logging_conn_loss(f"*----Frames pattern above----*\n", init_logs.frames_till_disr_data)
                                frames_till_disr = []
                                break
                            else:
                                sendp(frame, count=16, iface=self.interface, verbose=0)
                subprocess.call(['clear'], shell=True)
                counter += 1       
