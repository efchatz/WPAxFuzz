from Mngmt_frames.Construct_frame_fields import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
from random import randint

class Beacon(Frame):

    def __init__(self, generator, mode, frame_name, dest_addr, source_addr, interface, ssid, direction):
        super(Beacon, self).__init__()
        self.generator = generator
        self.mode = mode
        self.frame_name = frame_name
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.ssid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        self.direction = direction
        self.fuzzer_state = {
            "empty": {
                "send_function": self.MAC_header,
                "conn_loss": False
                },
            "timestamps and intervals": {
                "send_function": self.send_beacon_with_rand_timestamp_interval,
                "conn_loss": False
                },
            "capabilities": {
                "send_function": self.send_beacon_with_rand_capabilities,
                "conn_loss": False
                },
            "SSIDs": {
                "send_function": self.send_beacon_with_rand_SSID,
                "conn_loss": False
                },
            "supported rates": {
                "send_function": self.send_beacon_with_rand_supp_speed,
                "conn_loss": False
                },
            "DSset": {
                "send_function": self.send_beacon_with_rand_DSset,
                "conn_loss": False
                },
            "TIM values": {
                "send_function": self.send_beacon_with_rand_TIM,
                "conn_loss": False
                },
            "RM enabled capabilities": {
                "send_function": self.send_beacon_with_rand_RM_enabled_capabilities,
                "conn_loss": False
                },
            "HT capabilities": {
                "send_function": self.send_beacon_with_rand_HT_capabilities,
                "conn_loss": False
                },
            "HT information": {
                "send_function": self.send_beacon_with_rand_HT_information,
                "conn_loss": False
                },
            "extended capabilities": {
                "send_function": self.send_beacon_with_rand_extended_HT_capabilities,
                "conn_loss": False
                },
            "RSNs": {
                "send_function": self.send_beacon_with_rand_RSN,
                "conn_loss": False
                },
            "source MACs": {
                "send_function": self.send_beacon_with_rand_source_mac,
                "conn_loss": False
                },
            "all fields": {
                "send_function": self.send_beacon_with_all_fields_rand,
                "conn_loss": False
            }
        }
       
    def MAC_header(self, mode):
        if mode == 'standard':
            MAC_header = self.construct_MAC_header(8, 'ff:ff:ff:ff:ff:ff', self.source_addr, self.source_addr)
        elif mode == 'random':
            if self.direction == 1:
                MAC_header = self.construct_MAC_header(8, 'ff:ff:ff:ff:ff:ff', self.source_addr, self.source_addr)
            elif self.direction == 2:
                MAC_header = self.construct_MAC_header(8, self.source_addr, self.dest_addr, self.source_addr)
        return MAC_header

    def send_beacon_with_rand_timestamp_interval(self, mode):
        beacon = Dot11Beacon(timestamp=randint(1, 9999), beacon_interval=randint(1, 9999), cap='ESS+privacy')
        frame = self.MAC_header(mode) / beacon / self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_EXT_HT_CAPABILITIES / STANDARD_TIM / STANDARD_RM_CAPS / STANDARD_RSN
        return frame
        
    def send_beacon_with_rand_capabilities(self, mode):
        beacon = Dot11Beacon(cap=randint(1, 9999))
        frame = self.MAC_header(mode) / beacon / self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_EXT_HT_CAPABILITIES / STANDARD_TIM / STANDARD_RM_CAPS / STANDARD_RSN
        return frame

    def send_beacon_with_rand_SSID(self, mode):
        beacon = Dot11Beacon(cap='ESS+privacy')
        frame = self.MAC_header(mode) / beacon / self.generate_SSID(self.generator, mode) / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_EXT_HT_CAPABILITIES / STANDARD_TIM / STANDARD_RM_CAPS / STANDARD_RSN
        return frame

    def send_beacon_with_rand_RSN(self, mode):
        beacon = Dot11Beacon(cap='ESS+privacy')
        frame = self.MAC_header(mode) / beacon / self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_EXT_HT_CAPABILITIES / STANDARD_TIM / STANDARD_RM_CAPS / self.construct_RSN(self.generator, mode)
        return frame

    def send_beacon_with_rand_source_mac(self, mode):
        beacon = Dot11Beacon(cap='ESS+privacy')
        frame = self.construct_MAC_header(8, 'ff:ff:ff:ff:ff:ff', self.generate_MAC(self.generator), self.source_addr) / beacon / self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_EXT_HT_CAPABILITIES / STANDARD_TIM / STANDARD_RM_CAPS / STANDARD_RSN
        return frame

    def send_beacon_with_rand_TIM(self, mode):
        beacon = Dot11Beacon(cap='ESS+privacy')
        frame = self.MAC_header(mode) / beacon / self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_EXT_HT_CAPABILITIES / self.construct_TIM(self.generator,mode) / STANDARD_RM_CAPS / STANDARD_RSN
        return frame

    def send_beacon_with_rand_supp_speed(self, mode):
        beacon = Dot11Beacon(cap='ESS+privacy')
        frame = self.MAC_header(mode) / beacon / self.ssid / self.generate_supp_speed(self.generator, mode) / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION/ STANDARD_EXT_HT_CAPABILITIES / STANDARD_TIM / STANDARD_RM_CAPS / STANDARD_RSN
        return frame

    def send_beacon_with_rand_DSset(self, mode):
        beacon = Dot11Beacon(cap='ESS+privacy')
        frame = self.MAC_header(mode) / beacon / self.ssid / SUPPORTED_RATES / SUPPL_RATES / self.generate_channel_use(self.generator, mode) / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_EXT_HT_CAPABILITIES/\
                STANDARD_TIM / STANDARD_RM_CAPS / STANDARD_RSN
        return frame

    def send_beacon_with_rand_HT_capabilities(self, mode):
        beacon = Dot11Beacon(cap='ESS+privacy')
        frame = self.MAC_header(mode) / beacon / self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / self.generate_HT_capabilities(self.generator, mode) / STANDARD_HT_INFORMATION / STANDARD_EXT_HT_CAPABILITIES / STANDARD_TIM / STANDARD_RM_CAPS / STANDARD_RSN
        return frame

    def send_beacon_with_rand_RM_enabled_capabilities(self, mode):
        beacon = Dot11Beacon(cap='ESS+privacy')
        frame = self.MAC_header(mode) / beacon / self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / STANDARD_EXT_HT_CAPABILITIES / STANDARD_TIM / self.generate_RM_enabled_capabilities(self.generator, mode) / STANDARD_RSN
        return frame

    def send_beacon_with_rand_HT_information(self, mode):
        beacon = Dot11Beacon(cap='ESS+privacy')
        frame = self.MAC_header(mode) / beacon / self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / self.generate_HT_information(self.generator, mode) / STANDARD_EXT_HT_CAPABILITIES / STANDARD_TIM / STANDARD_RM_CAPS / STANDARD_RSN
        return frame

    def send_beacon_with_rand_extended_HT_capabilities(self, mode):
        beacon = Dot11Beacon(cap='ESS+privacy')
        frame = self.MAC_header(mode) / beacon / self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_DS / STANDARD_HT_CAPABILITIES / STANDARD_HT_INFORMATION / self.generate_extended_HT_capabilities(self.generator, mode) / STANDARD_TIM / STANDARD_RM_CAPS / STANDARD_RSN
        return frame

    def send_beacon_with_all_fields_rand(self, mode):
        beacon = Dot11Beacon(timestamp=randint(1, 9999), beacon_interval=randint(1, 9999), cap=randint(1, 9999))
        frame = self.MAC_header(mode) / beacon / self.ssid / self.generate_supp_speed(self.generator, mode) / self.generate_channel_use(self.generator, mode) / self.generate_HT_capabilities(self.generator, mode) / self.generate_HT_information(self.generator, mode) / self.generate_extended_HT_capabilities(self.generator, mode) / self.construct_TIM(self.generator, mode) /self.generate_RM_enabled_capabilities(self.generator, mode) / self.construct_RSN(mode)
        return frame

    def fuzz_beacon(self):
        self.fuzz(self.mode, self.fuzzer_state, self.interface)
