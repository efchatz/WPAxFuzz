from Mngmt_frames.ActionFrames import Dot11Block, Dot11DELBA, Dot11ADDBARequest, Dot11ADDBAResponse
from Mngmt_frames.Construct_frame_fields import *
from scapy.layers.dot11 import Dot11Action, Dot11SpectrumManagement, Dot11WNM, Dot11EltCSA, Dot11BSSTMRequest, Dot11BSSTMResponse


class Action(Frame):
    def __init__(self, generator, mode, frame_name, dest_addr, source_addr, interface):
        super(Action, self).__init__()
        self.generator = generator
        self.mode = mode
        self.frame_name = frame_name
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.fuzzer_state = {
            "Spectrum Management": {
                "send_function": self.send_Spectrum_Management,
                "conn_loss": False
            },
            "WNM": {
                "send_function": self.send_WNM,
                "conn_loss": False
            },
            "Block Ack": {
                "send_function": self.send_Block_Ack,
                "conn_loss": False
            }
        }

    def send_empty_action(self, mode):
        return self.construct_MAC_header(13, self.dest_addr, self.source_addr, self.source_addr)

    def send_Spectrum_Management(self, action_value):
        category = Dot11Action(category=0x00)
        action_code = Dot11SpectrumManagement(action=action_value)
        frame = self.construct_MAC_header(13, self.dest_addr, self.source_addr, self.source_addr) / category / action_code / \
                Dot11EltCSA(ID=random.randint(0,221), mode=random.randint(0,7))
        return frame

    def send_WNM(self, action_value):
        category = Dot11Action(category=0x0A)
        action_code = Dot11WNM(action=action_value)
        if action_value == 0x07:
            return self.construct_MAC_header(13, self.dest_addr, self.source_addr, self.source_addr) / category / action_code / \
                Dot11BSSTMRequest(token=random.randint(0,192), mode=random.randint(0,31), disassociation_timer=random.randint(0,65535), validity_interval=0,)
        elif action_value == 0x08:
            return self.construct_MAC_header(13, self.dest_addr, self.source_addr, self.source_addr) / category / action_code / \
                Dot11BSSTMResponse(token=random.randint(0,192), status=random.randint(0,8))
        frame = self.construct_MAC_header(13, self.dest_addr, self.source_addr, self.source_addr) / category / action_code
        return frame

    def send_Block_Ack(self, action_value):
        category = Dot11Action(category=0x03)
        action_code = Dot11Block(action=action_value)
        match action_value:
            case 0x00:
                frame = self.construct_MAC_header(13, self.dest_addr, self.source_addr, self.source_addr) / category / action_code / Dot11ADDBARequest(block_ack_timeout_value=random.randint(0,65535))
            case 0x01:
                frame = self.construct_MAC_header(13, self.dest_addr, self.source_addr, self.source_addr) / category / action_code / Dot11ADDBAResponse(status_code=random.randint(0,102),block_ack_timeout_value=random.randint(0,65535))
            case 0x02:
                frame = self.construct_MAC_header(13, self.dest_addr, self.source_addr, self.source_addr) / category / action_code / Dot11DELBA(reason_code=generate_bytes(2, self.generator, self.mode))
        return frame

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

    def fuzz_action(self):
        init_logs = LogFiles()
        counter = 1
        frames_till_disr = []
        caused_disc = [(999, 999, 999)]
        subprocess.call(['clear'], shell=True)
        print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ')
        print('You selected mode:', self.mode)
        while True:
            frames_till_disr = []
            subprocess.call(['echo' + f' Fuzzing cycle No.{counter}\n'], shell=True)
            subprocess.call(['echo' + f' {bcolors.OKGREEN}Stop the fuzzing and monitoring processes with 2 consecutive Ctrl+c{bcolors.ENDC}\n'], shell=True)
            print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
            for i in self.fuzzer_state:
                if self.fuzzer_state[i]["conn_loss"]:
                    continue
                subprocess.call(
                    ['echo' + f' Transmitting {2*NUM_OF_FRAMES_TO_SEND} {i} {bcolors.OKBLUE}{self.frame_name} - {bcolors.ENDC} frames'], shell=True)
                if i == 'Spectrum Management':
                    for action_value in range(0x00, 0x04):
                        for _ in range(1, NUM_OF_FRAMES_TO_SEND):
                            frame = self.fuzzer_state[i]["send_function"](action_value)
                            frames_till_disr += frame
                            if self.fuzzer_state[i]["conn_loss"]:
                                break
                            if self.check_conn_aliveness(frame, i):
                                init_logs.logging_conn_loss(f"Connectivity issues detected while sending Spectrum Management {self.frame_name} frames\nframe = {frame}\n\n", init_logs.is_alive_path_mngmt)
                                init_logs.logging_conn_loss(f"Prior to connection loss found the above frames were sent. Timestamp of logging is cycle {counter}\n", init_logs.frames_till_disr_mngmt)
                                for item in frames_till_disr:
                                    init_logs.logging_conn_loss(f"\nframe = {item}\n\n", init_logs.frames_till_disr_mngmt)
                                init_logs.logging_conn_loss(f"*----Frames pattern above----*\n", init_logs.frames_till_disr_mngmt)
                                frames_till_disr = []
                                break
                            else:
                                sendp(frame, count=2, iface=self.interface, verbose=0)
                elif i == 'WNM':
                    for action_value in range(0x00, 0x1C):
                        for _ in range(1, NUM_OF_FRAMES_TO_SEND):
                            frame = self.fuzzer_state[i]["send_function"](action_value)
                            frames_till_disr += frame
                            if self.check_conn_aliveness(frame, i):
                                init_logs.logging_conn_loss(f"Connectivity issues detected while sending WNM {self.frame_name} frames\nframe = {frame}\n\n", init_logs.is_alive_path_mngmt)
                                init_logs.logging_conn_loss(f"Prior to connection loss found the above frames were sent. Timestamp of logging is cycle {counter}\n", init_logs.frames_till_disr_mngmt)
                                for item in frames_till_disr:
                                    init_logs.logging_conn_loss(f"\nframe = {item}\n\n", init_logs.frames_till_disr_mngmt)
                                init_logs.logging_conn_loss(f"*----Frames pattern above----*\n", init_logs.frames_till_disr_mngmt)
                                frames_till_disr = []
                                break
                            else:
                                sendp(frame, count=2, iface=self.interface, verbose=0)
                elif i == 'Block Ack':
                    for action_value in range(0x00, 0x02):
                        for _ in range(1, NUM_OF_FRAMES_TO_SEND):
                            frame = self.fuzzer_state[i]["send_function"](action_value)
                            frames_till_disr += frame
                            if self.check_conn_aliveness(frame, i):
                                init_logs.logging_conn_loss(f"Connectivity issues detected while sending Block Ack {self.frame_name} frames\nframe = {frame}\n\n", init_logs.is_alive_path_mngmt)
                                init_logs.logging_conn_loss(f"Prior to connection loss found the above frames were sent. Timestamp of logging is cycle {counter}\n", init_logs.frames_till_disr_mngmt)
                                for item in frames_till_disr:
                                    init_logs.logging_conn_loss(f"\nframe = {item}\n\n", init_logs.frames_till_disr_mngmt)
                                init_logs.logging_conn_loss(f"*----Frames pattern above----*\n", init_logs.frames_till_disr_mngmt)
                                frames_till_disr = []
                                break
                            else:
                                sendp(frame, count=2, iface=self.interface, verbose=0)
            subprocess.call(['clear'], shell=True)
            counter += 1
