from random import randint

from Mngmt_frames.Construct_frame_fields import *
from scapy.layers.dot11 import Dot11AssoResp, Dot11Elt


class AssoResp(Frame):

    def __init__(self, generator, mode, frame_name, dest_addr, source_addr, interface, direction):
        super(AssoResp, self).__init__()
        self.generator = generator
        self.mode = mode
        self.frame_name = frame_name
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.direction = direction
        self.fuzzer_state = {
            "empty": {
                "send_function": self.MAC_header,
                "conn_loss": False
            },
            "capabilities": {
                "send_function": self.send_asso_resp_with_rand_capabilities,
                "conn_loss": False
            },
            "supported rates": {
                "send_function": self.send_asso_resp_with_rand_supp_speed,
                "conn_loss": False
            },
            "HT capabilities": {
                "send_function": self.send_asso_resp_with_rand_HT_capabilities,
                "conn_loss": False
            },
            "HT information": {
                "send_function": self.send_asso_resp_with_rand_HT_information,
                "conn_loss": False
            },
            "overlapping BSS scan parameters": {
                "send_function": self.send_asso_resp_with_rand_overlapping_BSS,
                "conn_loss": False
            },
            "extended capabilities": {
                "send_function": self.send_asso_resp_with_rand_extended_HT_caps,
                "conn_loss": False
            },
            "source MACs": {
                "send_function": self.send_asso_resp_with_rand_source_mac,
                "conn_loss": False
            },
            "all fields": {
                "send_function": self.send_asso_resp_with_all_fields_rand,
                "conn_loss": False
            },
        }

    def MAC_header(self, mode):
        if mode == 'standard':
            MAC_header = self.construct_MAC_header(1, self.dest_addr, self.source_addr, self.source_addr)
        elif mode == 'random':
            if self.direction == 1:
                MAC_header = self.construct_MAC_header(1, self.dest_addr, self.source_addr, self.source_addr)
            elif self.direction == 2:
                MAC_header = self.construct_MAC_header(1, self.source_addr, self.dest_addr, self.source_addr)
        return MAC_header

    def send_asso_resp_with_rand_source_mac(self, mode):
        asso_resp = Dot11AssoResp(cap=4920)
        frame = self.MAC_header(mode) / asso_resp / SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES
        return frame
        
    def send_asso_resp_with_rand_capabilities(self, mode):
        asso_resp = Dot11AssoResp(cap=randint(1,9999))
        frame = self.MAC_header(mode) / asso_resp / SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_asso_resp_with_rand_supp_speed(self, mode):
        asso_resp = Dot11AssoResp(cap=4920)
        frame = self.MAC_header(mode) / asso_resp / self.generate_supp_speed(self.generator, mode) / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_asso_resp_with_rand_HT_capabilities(self, mode):
        asso_resp = Dot11AssoResp(cap=4920)
        frame = self.MAC_header(mode) / asso_resp / SUPPORTED_RATES / SUPPL_RATES / self.generate_HT_capabilities(self.generator, mode) / STANDARD_HT_INFORMATION / STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_asso_resp_with_rand_HT_information(self, mode):
        asso_resp = Dot11AssoResp(cap=4920)
        frame = self.MAC_header(mode) / asso_resp / SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / self.generate_HT_information(self.generator, mode) / STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_asso_resp_with_rand_overlapping_BSS(self, mode):
        asso_resp = Dot11AssoResp(cap=4920)
        frame = self.MAC_header(mode) / asso_resp / SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / self.generate_overlapping_BSS(self.generator, mode) / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_asso_resp_with_rand_extended_HT_caps(self, mode):
        asso_resp = Dot11AssoResp(cap=4920)
        frame = self.MAC_header(mode) / asso_resp / SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_OVERLAPPING_BSS / self.generate_extended_HT_capabilities(self.generator, mode)
        return frame

    def send_asso_resp_with_all_fields_rand(self, mode):
        asso_resp = Dot11AssoResp(cap=randint(1, 9999))
        frame = self.MAC_header(mode) / asso_resp / self.generate_supp_speed(self.generator, mode) / self.generate_HT_capabilities(self.generator, mode) / self.generate_HT_information(self.generator, mode) / self.generate_overlapping_BSS(self.generator, mode) / self.generate_extended_HT_capabilities(self.generator, mode)
        return frame
        
    def fuzz_asso_resp(self):
        self.fuzz(self.mode, self.fuzzer_state, self.interface)
