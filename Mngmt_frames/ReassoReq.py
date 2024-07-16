from random import randint

from Mngmt_frames.Construct_frame_fields import *
from scapy.layers.dot11 import Dot11ReassoReq, Dot11Elt


class ReassoReq(Frame):
    def __init__(self, generator, mode, frame_name, dest_addr, source_addr, interface, ssid):
        super(ReassoReq, self).__init__()
        self.generator = generator
        self.mode = mode
        self.frame_name = frame_name
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.ssid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        self.fuzzer_state = {
            "empty": {
                "send_function": self.send_empty_reasso_req,
                "conn_loss": False
            },
            "capabilities": {
                "send_function": self.send_reasso_req_with_rand_capabilities,
                "conn_loss": False
            },
            "current AP": {
                "send_function": self.send_reasso_req_with_rand_current_AP,
                "conn_loss": False
            },
            "supported rates": {
                "send_function": self.send_reasso_req_with_rand_supp_speed,
                "conn_loss": False
            },
            "power capabilities": {
                "send_function": self.send_reasso_req_with_rand_power_caps,
                "conn_loss": False
            },
            "supported channels": {
                "send_function": self.send_reasso_req_with_rand_supp_channels,
                "conn_loss": False
            },
            "RSNs": {
                "send_function": self.send_reasso_req_with_rand_RSN,
                "conn_loss": False
            },
            "RM enabled capabilities": {
                "send_function": self.send_reasso_req_with_rand_RM_caps,
                "conn_loss": False
            },
            "HT capabilities": {
                "send_function": self.send_reasso_req_with_rand_HT_capabilities,
                "conn_loss": False
            },
            "extended HT capabilities": {
                "send_function": self.send_reasso_req_with_rand_ext_HT_capabilities,
                "conn_loss": False
            },
            "source MACs": {
                "send_function": self.send_reasso_req_with_rand_source_mac,
                "conn_loss": False
            },
            "all fields": {
                "send_function": self.send_reasso_req_with_all_fields_rand,
                "conn_loss": False
            },
        }

    def send_empty_reasso_req(self, mode):
        return self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr)

    def send_reasso_req_with_rand_RSN(self, mode):
        reasso_req = Dot11ReassoReq(cap=4920, current_AP=STANDARD_MAC_ADDRESS)
        frame = self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr) / reasso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / self.construct_RSN(mode) /\
                STANDARD_RM_CAPS / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_reasso_req_with_rand_source_mac(self, mode):
        reasso_req = Dot11ReassoReq(cap=4920, current_AP=STANDARD_MAC_ADDRESS)
        frame = self.construct_MAC_header(2, self.dest_addr, self.generate_MAC(self.generator), self.dest_addr) / reasso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_RM_CAPS / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_reasso_req_with_rand_current_AP(self, mode):
        reasso_req = Dot11ReassoReq(cap=4920, current_AP=self.generate_MAC(self.generator))
        frame = self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr) / reasso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_RM_CAPS / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_reasso_req_with_rand_capabilities(self, mode):
        reasso_req = Dot11ReassoReq(cap=randint(1, 9999), current_AP=STANDARD_MAC_ADDRESS)
        frame = self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr) / reasso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_RM_CAPS / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_reasso_req_with_rand_supp_speed(self, mode):
        reasso_req = Dot11ReassoReq(cap=4920, current_AP=STANDARD_MAC_ADDRESS)
        frame = self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr) / reasso_req / \
                self.ssid / self.generate_supp_speed(self.generator, mode) / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_RM_CAPS / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_reasso_req_with_rand_HT_capabilities(self, mode):
        reasso_req = Dot11ReassoReq(cap=4920, current_AP=STANDARD_MAC_ADDRESS)
        frame = self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr) / reasso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_RM_CAPS / self.generate_HT_capabilities(self.generator, mode) / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_reasso_req_with_rand_ext_HT_capabilities(self, mode):
        reasso_req = Dot11ReassoReq(cap=4920, current_AP=STANDARD_MAC_ADDRESS)
        frame = self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr) / reasso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_RM_CAPS / STANDARD_HT_CAPABILITIES / self.generate_extended_HT_capabilities(self.generator, mode)
        return frame

    def send_reasso_req_with_rand_power_caps(self, mode):
        reasso_req = Dot11ReassoReq(cap=4920, current_AP=STANDARD_MAC_ADDRESS)
        frame = self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr) / reasso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / self.generate_power_capability(self.generator, mode) / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                STANDARD_RM_CAPS / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_reasso_req_with_rand_supp_channels(self, mode):
        reasso_req = Dot11ReassoReq(cap=4920, current_AP=STANDARD_MAC_ADDRESS)
        frame = self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr) / reasso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / self.generate_supported_channels(self.generator, mode) / STANDARD_RSN /\
                STANDARD_RM_CAPS / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_reasso_req_with_rand_RM_caps(self, mode):
        reasso_req = Dot11ReassoReq(cap=4920, current_AP=STANDARD_MAC_ADDRESS)
        frame = self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr) / reasso_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN /\
                self.generate_RM_enabled_capabilities(self.generator, mode) / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_reasso_req_with_all_fields_rand(self, mode):
        reasso_req = Dot11ReassoReq(cap=randint(1, 9999), current_AP=self.generate_MAC(self.generator))
        frame = self.construct_MAC_header(2, self.dest_addr, self.source_addr, self.dest_addr) / reasso_req / \
                self.ssid / self.generate_supp_speed(self.generator, mode) / self.generate_power_capability(self.generator, mode) / self.generate_supported_channels(self.generator, mode) / self.construct_RSN(mode) / self.generate_RM_enabled_capabilities(self.generator, mode) / self.generate_HT_capabilities(self.generator, mode) / self.generate_extended_HT_capabilities(self.generator, mode)
        return frame

    def fuzz_reasso_req(self):
        self.fuzz(self.mode, self.fuzzer_state, self.interface)
