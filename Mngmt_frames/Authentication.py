from Mngmt_frames.Construct_frame_fields import *
from Msgs_colors import bcolors
from Logging import LogFiles
from scapy.layers.dot11 import Dot11Auth, Dot11Elt
from random import randint

class Authentication(Frame):
    def __init__(self, fuzzer, mode, frame_name, dest_addr, source_addr, interface):
        super(Authentication, self).__init__()
        self.fuzzer = fuzzer
        self.mode = mode
        self.frame_name = frame_name
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.algo_vals = [0, 1, 200]
        self.sequence_vals = [1, 2, 3, 4, 200]
        self.status_vals = [0, 1, 200]
        self.fuzzer_state = {
            "empty": {
                "send_function": self.send_empty_auth,
                "conn_loss": False
            },
            "authentication algorithm": {
                "send_function": self.send_auth_with_rand_algo,
                "conn_loss": False
            },
            "sequence number": {
                "send_function": self.send_auth_with_rand_seqnum,
                "conn_loss": False
            },
            "status": {
                "send_function": self.send_auth_with_rand_status,
                "conn_loss": False
            },
            "all fields": {
                "send_function": self.send_auth_with_all_fields_rand,
                "conn_loss": False
            },
            "allowed": {
                "send_function": self.fuzz_for_allowed_values,
                "conn_loss": False
            },
        }

    def send_empty_auth(self, mode):
        return self.construct_MAC_header(11, self.dest_addr, self.source_addr, self.dest_addr)

    def send_auth_with_rand_algo(self, mode):
        auth = Dot11Auth(algo=randint(1, 9999), seqnum=1, status=0)
        frame = self.construct_MAC_header(11, self.dest_addr, self.source_addr, self.dest_addr) / auth
        return frame

    def send_auth_with_rand_seqnum(self, mode):
        auth = Dot11Auth(algo=0, seqnum=randint(1, 9999), status=0)
        frame = self.construct_MAC_header(11, self.dest_addr, self.source_addr, self.dest_addr) / auth
        return frame

    def send_auth_with_rand_status(self, mode):
        auth = Dot11Auth(algo=0, seqnum=1, status=randint(1, 65535))
        frame = self.construct_MAC_header(11, self.dest_addr, self.source_addr, self.dest_addr) / auth
        return frame

    def send_auth_with_all_fields_rand(self, mode):
        auth = Dot11Auth(algo=randint(1, 9999), seqnum=randint(1, 9999), status=randint(1, 65535))
        frame = self.construct_MAC_header(11, self.dest_addr, self.source_addr, self.dest_addr) / auth
        return frame

    def fuzz_for_allowed_values(self, caused_disc):
        init_logs = LogFiles()

        def is_payload_reused(conn_loss_vals):    
            for item in conn_loss_vals:
                if algo == item[0] and seq == item[1] and status == item[2]:
                    return True
            return False
            
        for algo in self.algo_vals:
            for seq in self.sequence_vals:
                for status in self.status_vals:
                    if is_payload_reused(caused_disc):
                        break
                    else:
                        subprocess.call([
                        'echo' + f' Transmiting {bcolors.OKBLUE}authentication{bcolors.ENDC} frames with'
                                 f' authentication algorithm number {algo}, sequence number {seq} and'
                                 f' status {status}'],
                        shell=True)
                        for _ in range(1, NUM_OF_FRAMES_TO_SEND):
                            auth = Dot11Auth(algo=algo, seqnum=seq, status=status)
                            frame = self.construct_MAC_header(11, self.dest_addr, self.source_addr, self.dest_addr) / auth
                            if self.check_conn_aliveness(frame):
                                caused_disc.append((algo, seq, status))
                                init_logs.logging_conn_loss(f"onnectivity issues detected while sending {self.frame_name} frames with authentication algorithm: {algo}, sequence number: {seq} and status: {status}\nframe = {frame}\n\n", init_logs.is_alive_path_mngmt)
                            else:
                                self.send_Frame(frame, self.interface)
        return caused_disc

    def fuzz_auth(self):
        self.fuzz(self.mode, self.fuzzer_state, self.interface, True)
