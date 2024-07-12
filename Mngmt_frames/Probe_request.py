from Mngmt_frames.Construct_frame_fields import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11Elt


class ProbeReq(Frame):
    def __init__(self, fuzzer, mode, frame_name, dest_addr, source_addr, interface, ssid):
        super(ProbeReq, self).__init__()
        self.fuzzer = fuzzer
        self.mode = mode
        self.frame_name = frame_name
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.ssid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        self.fuzzer_state = {
            "empty": {
                "send_function": self.send_empty_Probe_req,
                "conn_loss": False
            },
            "supported rates": {
                "send_function": self.send_Probe_req_with_rand_supp_speed,
                "conn_loss": False
            },
            "DSset": {
                "send_function": self.send_Probe_req_with_rand_DSset,
                "conn_loss": False
            },
            "HT capabilities": {
                "send_function": self.send_Probe_req_with_rand_HT_capabilities,
                "conn_loss": False
            },
            "extended capabilities": {
                "send_function": self.send_Probe_req_with_rand_ext_HT_capabilities,
                "conn_loss": False
            },
            "RSNs": {
                "send_function": self.send_Probe_req_with_rand_RSN,
                "conn_loss": False
            },
            "source MACs": {
                "send_function": self.send_Probe_req_with_rand_source_mac,
                "conn_loss": False
            },
            "all fields": {
                "send_function": self.send_Probe_req_with_all_fields_rand,
                "conn_loss": False
            },
        }

    def send_empty_Probe_req(self, mode):
        return self.construct_MAC_header(4, self.dest_addr, self.source_addr, self.dest_addr)

    def send_Probe_req_with_rand_RSN(self, mode):
        probe_req = Dot11ProbeReq()
        frame = self.construct_MAC_header(4, self.dest_addr, self.source_addr, self.dest_addr) / probe_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES / self.construct_RSN(self.fuzzer, mode)
        return frame

    def send_Probe_req_with_rand_source_mac(self, mode):
        probe_req = Dot11ProbeReq()
        frame = self.construct_MAC_header(4, self.dest_addr, self.generate_MAC(self.fuzzer), self.dest_addr) / probe_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES / STANDARD_RSN
        return frame

    def send_Probe_req_with_rand_supp_speed(self, mode):
        probe_req = Dot11ProbeReq()
        frame = self.construct_MAC_header(4, self.dest_addr, self.source_addr, self.dest_addr) / probe_req / \
                self.ssid / self.generate_supp_speed(self.fuzzer, mode) / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES / STANDARD_RSN
        return frame

    def send_Probe_req_with_rand_DSset(self, mode):
        probe_req = Dot11ProbeReq()
        frame = self.construct_MAC_header(4, self.dest_addr, self.source_addr, self.dest_addr) / probe_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / self.generate_channel_use(self.fuzzer, mode) / STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES / STANDARD_RSN
        return frame

    def send_Probe_req_with_rand_HT_capabilities(self, mode):
        probe_req = Dot11ProbeReq()
        frame = self.construct_MAC_header(4, self.dest_addr, self.source_addr, self.dest_addr) / probe_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / self.generate_HT_capabilities(self.fuzzer, mode) / STANDARD_EXT_HT_CAPABILITIES / STANDARD_RSN
        return frame

    def send_Probe_req_with_rand_ext_HT_capabilities(self, mode):
        probe_req = Dot11ProbeReq()
        frame = self.construct_MAC_header(4, self.dest_addr, self.source_addr, self.dest_addr) / probe_req / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / self.generate_extended_HT_capabilities(self.fuzzer, mode) / STANDARD_RSN
        return frame

    def send_Probe_req_with_all_fields_rand(self, mode):
        probe_req = Dot11ProbeReq()
        frame = self.construct_MAC_header(4, self.dest_addr, self.source_addr, self.dest_addr) / probe_req / \
                self.ssid / self.generate_supp_speed(self.fuzzer, mode) / self.generate_channel_use(self.fuzzer, mode) / self.generate_HT_capabilities(self.fuzzer, mode) / self.generate_extended_HT_capabilities(self.fuzzer, mode) / self.construct_RSN(mode)
        return frame

    def fuzz_probe_req(self):
        self.fuzz(self.mode, self.fuzzer_state, self.interface)
