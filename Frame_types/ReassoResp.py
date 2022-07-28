from Frame_types.Construct_frame_fields import *
from scapy.all import Dot11ReassoResp, Dot11Elt

class ReassoResp(Frame):
    def __init__(self, mode, frame_name, dest_addr, source_addr, interface, direction):
        super(ReassoResp, self).__init__()
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
                "send_function": self.send_Reasso_resp_with_rand_capabilities,
                "conn_loss": False
            },
            "supported rates": {
                "send_function": self.send_Reasso_resp_with_rand_supp_speed,
                "conn_loss": False
            },
            "HT capabilities": {
                "send_function": self.send_Reasso_resp_with_rand_HT_capabilities,
                "conn_loss": False
            },
            "HT information": {
                "send_function": self.send_Reasso_resp_with_rand_HT_information,
                "conn_loss": False
            },
            "overlapping BSS scan parameters": {
                "send_function": self.send_Reasso_resp_with_rand_overlapping_BSS,
                "conn_loss": False
            },
            "extended HT capabilities": {
                "send_function": self.send_Reasso_resp_with_rand_ext_HT_capabilities,
                "conn_loss": False
            },
            "RM enabled capabilities": {
                "send_function": self.send_Reasso_resp_with_rand_RM_caps,
                "conn_loss": False
            },
            "source MACs": {
                "send_function": self.send_Reasso_resp_with_rand_source_mac,
                "conn_loss": False
            },
            "all fields": {
                "send_function": self.send_Reasso_resp_with_all_fields_rand,
                "conn_loss": False
            },
        }

    def MAC_header(self, mode):
        if mode == 'standard':
            MAC_header = self.construct_MAC_header(3, self.dest_addr, self.source_addr, self.source_addr)
        elif mode == 'random':
            if self.direction == 1:
                MAC_header = self.construct_MAC_header(3, self.dest_addr, self.source_addr, self.source_addr)
            elif self.direction == 2:
                MAC_header = self.construct_MAC_header(3, self.source_addr, self.dest_addr, self.source_addr)
        return MAC_header

    def send_Reasso_resp_with_rand_source_mac(self, mode):
        reasso_resp = Dot11ReassoResp(cap=4920)
        frame = self.construct_MAC_header(3, self.dest_addr, self.generate_MAC(), self.source_addr) / reasso_resp / \
                SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / \
                STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES / STANDARD_RM_CAPS
        return frame

    def send_Reasso_resp_with_rand_capabilities(self, mode):
        reasso_resp = Dot11ReassoResp(cap=randint(1, 9999))
        frame = self.MAC_header(mode) / reasso_resp / SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION /STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES / STANDARD_RM_CAPS
        return frame

    def send_Reasso_resp_with_rand_supp_speed(self, mode):
        reasso_resp = Dot11ReassoResp(cap=4920)
        frame = self.MAC_header(mode) / reasso_resp / self.generate_supp_speed(mode) / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES / STANDARD_RM_CAPS
        return frame

    def send_Reasso_resp_with_rand_HT_capabilities(self, mode):
        reasso_resp = Dot11ReassoResp(cap=4920)
        frame = self.MAC_header(mode) / reasso_resp / SUPPORTED_RATES / SUPPL_RATES / self.generate_HT_capabilities(mode) / STANDARD_HT_INFORMATION / STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES / STANDARD_RM_CAPS
        return frame

    def send_Reasso_resp_with_rand_HT_information(self, mode):
        reasso_resp = Dot11ReassoResp(cap=4920)
        frame = self.MAC_header(mode) / reasso_resp / SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / self.generate_HT_information(mode) / STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES / STANDARD_RM_CAPS
        return frame

    def send_Reasso_resp_with_rand_overlapping_BSS(self, mode):
        reasso_resp = Dot11ReassoResp(cap=4920)
        frame = self.MAC_header(mode) / reasso_resp / SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / self.generate_overlapping_BSS(mode) / STANDARD_EXT_HT_CAPABILITIES / STANDARD_RM_CAPS
        return frame

    def send_Reasso_resp_with_rand_ext_HT_capabilities(self, mode):
        reasso_resp = Dot11ReassoResp(cap=4920)
        frame = self.MAC_header(mode) / reasso_resp / SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_OVERLAPPING_BSS / self.generate_extended_HT_capabilities(mode) / STANDARD_RM_CAPS
        return frame

    def send_Reasso_resp_with_rand_RM_caps(self, mode):
        reasso_resp = Dot11ReassoResp(cap=4920)
        frame = self.MAC_header(mode) / reasso_resp / SUPPORTED_RATES / SUPPL_RATES / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_OVERLAPPING_BSS / STANDARD_EXT_HT_CAPABILITIES / self.generate_RM_enabled_capabilities(mode)
        return frame

    def send_Reasso_resp_with_all_fields_rand(self, mode):
        reasso_req = Dot11ReassoResp(cap=randint(1, 9999))
        frame = self.MAC_header(mode) / reasso_req / self.generate_supp_speed(mode) / self.generate_HT_capabilities(mode) / self.generate_HT_information(mode) / self.generate_overlapping_BSS(mode) / self.generate_extended_HT_capabilities(mode) / self.generate_RM_enabled_capabilities(mode)
        return frame

    def fuzz_reasso_resp(self):
        self.fuzz(self.mode, self.fuzzer_state, self.interface)
