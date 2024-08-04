from random import randint

from Mngmt_frames.Construct_frame_fields import *
from scapy.layers.dot11 import Dot11AssoReq, Dot11Elt


class AssoReq(Frame):
    def __init__(self, generator, mode, frame_name, dest_addr, source_addr, interface, ssid):
        super(AssoReq, self).__init__()
        self.generator = generator
        self.mode = mode
        self.frame_name = frame_name
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.ssid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        self.fuzzer_state = {
            "empty": {
                "send_function": self.send_empty_Asso_req,
                "conn_loss": False
            },
            "capabilities": {
                "send_function": self.send_Asso_req_with_rand_capabilities,
                "conn_loss": False
            },
            "supported rates": {
                "send_function": self.send_Asso_req_with_rand_supp_speed,
                "conn_loss": False
            },
            "power capabilities": {
                "send_function": self.send_Asso_req_with_rand_power_caps,
                "conn_loss": False
            },
            "supported channels": {
                "send_function": self.send_Asso_req_with_rand_supp_channels,
                "conn_loss": False
            },
            "RSNs": {
                "send_function": self.send_Asso_req_with_rand_RSN,
                "conn_loss": False
            },
            "HT capabilities": {
                "send_function": self.send_Asso_req_with_rand_HT_capabilities,
                "conn_loss": False
            },
            "extended capabilities": {
                "send_function": self.send_Asso_req_with_rand_ext_HT_capabilities,
                "conn_loss": False
            },
            "source MACs": {
                "send_function": self.send_Asso_req_with_rand_source_mac,
                "conn_loss": False
            },
            "all fields": {
                "send_function": self.send_Asso_req_with_all_fields_rand,
                "conn_loss": False
            },
        }

    def send_empty_Asso_req(self, mode):
        return self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr)

    def send_Asso_req_with_rand_RSN(self, mode):
        asso_req = Dot11AssoReq(cap=4920)
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / asso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / self.construct_RSN(self.generator, mode) /\
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_Asso_req_with_rand_source_mac(self, mode):
        asso_req = Dot11AssoReq(cap=4920)
        frame = self.construct_MAC_header(0, self.dest_addr, self.generate_MAC(self.generator), self.dest_addr) / asso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame
        
    def send_Asso_req_with_rand_capabilities(self, mode):
        asso_req = Dot11AssoReq(cap=randint(1,9999))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / asso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_Asso_req_with_rand_supp_speed(self, mode):
        asso_req = Dot11AssoReq(cap=4920)
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / asso_req / \
                self.ssid / self.generate_supp_speed(self.generator, mode) / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_Asso_req_with_rand_HT_capabilities(self, mode):
        asso_req = Dot11AssoReq(cap=4920)
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / asso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                self.generate_HT_capabilities(self.generator, mode) / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_Asso_req_with_rand_ext_HT_capabilities(self, mode):
        asso_req = Dot11AssoReq(cap=4920)
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / asso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_HT_CAPABILITIES / self.generate_extended_HT_capabilities(self.generator, mode)
        return frame

    def send_Asso_req_with_rand_power_caps(self, mode):
        asso_req = Dot11AssoReq(cap=4920)
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / asso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / self.generate_power_capability(self.generator, mode) / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_Asso_req_with_rand_supp_channels(self, mode):
        asso_req = Dot11AssoReq(cap=4920)
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / asso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / self.generate_supported_channels(self.generator, mode) / STANDARD_RSN /\
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_Asso_req_with_all_fields_rand(self, mode):
        asso_req = Dot11AssoReq(cap=randint(1, 9999))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / asso_req / \
                self.ssid / self.generate_supp_speed(self.generator, mode) / self.generate_power_capability(self.generator, mode) / self.generate_supported_channels(self.generator, mode) /\
                self.construct_RSN(self.generator, mode) / self.generate_HT_capabilities(self.generator, mode) / self.generate_extended_HT_capabilities(self.generator, mode)
        return frame

    def fuzz_asso_req(self):
        self.fuzz(self.mode, self.fuzzer_state, self.interface)
