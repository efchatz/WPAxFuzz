from Mngmt_frames.Construct_frame_fields import *
from scapy.layers.dot11 import Dot11Elt, Dot11Action


class Action(Frame):
    def __init__(self, generator, mode, frame_name, dest_addr, source_addr, interface, ssid):
        super(Action, self).__init__()
        self.generator = generator
        self.mode = mode
        self.frame_name = frame_name
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.ssid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        self.fuzzer_state = {
            "empty": {
                "send_function": self.send_empty_action,
                "conn_loss": False
            },
            "Event Request": {
                "send_function": self.send_event_req_action,
                "conn_loss": False
            },
            "Event Report": {
                "send_function": self.send_event_resp_action,
                "conn_loss": False
            },
            "Diagnostic Request": {
                "send_function": self.send_diagnostic_req_action,
                "conn_loss": False
            },
            "Diagnostic Report": {
                "send_function": self.send_diagnostic_report_action,
                "conn_loss": False
            },
            "Location Configuration Request": {
                "send_function": self.send_location_config_req_action,
                "conn_loss": False
            },
            "Location Configuration Response": {
                "send_function": self.send_location_config_resp_action,
                "conn_loss": False
            },
            "BSS Transition Management Query": {
                "send_function": self.send_bss_transition_management_query_action,
                "conn_loss": False
            },
            "BSS Transition Management Request": {
                "send_function": self.send_bss_transition_management_req_action,
                "conn_loss": False
            },
            "BSS Transition Management Response": {
                "send_function": self.send_bss_transition_management_resp_action,
                "conn_loss": False
            },
            "FMS Request": {
                "send_function": self.send_fms_req_action,
                "conn_loss": False
            },
            "FMS Response": {
                "send_function": self.send_fms_resp_action,
                "conn_loss": False
            },
            "Collocated Interference Request": {
                "send_function": self.send_collocated_interface_req_action,
                "conn_loss": False
            },
            "Collocated Interference Report": {
                "send_function": self.send_collocated_interface_report_action,
                "conn_loss": False
            },
            "TFS Request": {
                "send_function": self.send_tfs_req_action,
                "conn_loss": False
            },
            "TFS Response": {
                "send_function": self.send_tfs_resp_action,
                "conn_loss": False
            },
            "TFS Notify": {
                "send_function": self.send_tfs_notify_action,
                "conn_loss": False
            },
            "WNM Sleep Mode Request": {
                "send_function": self.send_wnm_sleep_mode_req_action,
                "conn_loss": False
            },
            "WNM Sleep Mode Response": {
                "send_function": self.send_wnm_sleep_mode_resp_action,
                "conn_loss": False
            },
            "TIM Broadcast Request": {
                "send_function": self.send_tim_broadcast_req_action,
                "conn_loss": False
            },
            "TIM Broadcast Response": {
                "send_function": self.send_tim_broadcast_resp_action,
                "conn_loss": False
            },
            "QoS Traffic Capability Update": {
                "send_function": self.send_qos_traffic_capability_update_action,
                "conn_loss": False
            },
            "Channel Usage Request": {
                "send_function": self.send_channel_usage_req_action,
                "conn_loss": False
            },
            "DMS Request": {
                "send_function": self.send_dms_req_action,
                "conn_loss": False
            },
            "DMS Response": {
                "send_function": self.send_dms_resp_action,
                "conn_loss": False
            },
            "Timing Measurement Request": {
                "send_function": self.send_timing_measurement_req_action,
                "conn_loss": False
            },
            "WNM Notification Request": {
                "send_function": self.send_wnm_notification_req_action,
                "conn_loss": False
            },
            "WNM Notification Response": {
                "send_function": self.send_wnm_notification_resp_action,
                "conn_loss": False
            },
            "WNM-Notify Response": {
                "send_function": self.send_wnm_notify_resp_action,
                "conn_loss": False
            },
        }

    def send_empty_action(self, mode):
        return self.construct_MAC_header(13, self.dest_addr, self.source_addr, self.dest_addr)

    def send_event_req_action(self, mode):
        action = Dot11Action(category=hex(0x00))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_event_resp_action(self, mode):
        action = Dot11Action(category=hex(0x01))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_diagnostic_req_action(self, mode):
        action = Dot11Action(category=hex(0x02))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_diagnostic_report_action(self, mode):
        action = Dot11Action(category=hex(0x03))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_location_config_req_action(self, mode):
        action = Dot11Action(category=hex(0x04))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_location_config_resp_action(self, mode):
        action = Dot11Action(category=hex(0x05))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_bss_transition_management_query_action(self, mode):
        action = Dot11Action(category=hex(0x06))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_bss_transition_management_req_action(self, mode):
        action = Dot11Action(category=hex(0x07))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_bss_transition_management_resp_action(self, mode):
        action = Dot11Action(category=hex(0x08))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_fms_req_action(self, mode):
        action = Dot11Action(category=hex(0x09))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_fms_resp_action(self, mode):
        action = Dot11Action(category=hex(0x0A))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_collocated_interface_req_action(self, mode):
        action = Dot11Action(category=hex(0x0B))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_collocated_interface_report_action(self, mode):
        action = Dot11Action(category=hex(0x0C))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_tfs_req_action(self, mode):
        action = Dot11Action(category=hex(0x0D))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_tfs_resp_action(self, mode):
        action = Dot11Action(category=hex(0x0E))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_tfs_notify_action(self, mode):
        action = Dot11Action(category=hex(0x0F))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_wnm_sleep_mode_req_action(self, mode):
        action = Dot11Action(category=hex(0x10))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_wnm_sleep_mode_resp_action(self, mode):
        action = Dot11Action(category=hex(0x11))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_tim_broadcast_req_action(self, mode):
        action = Dot11Action(category=hex(0x12))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_tim_broadcast_resp_action(self, mode):
        action = Dot11Action(category=hex(0x13))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_qos_traffic_capability_update_action(self, mode):
        action = Dot11Action(category=hex(0x14))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_channel_usage_req_action(self, mode):
        action = Dot11Action(category=hex(0x15))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_channel_usage_resp_action(self, mode):
        action = Dot11Action(category=hex(0x16))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_dms_req_action(self, mode):
        action = Dot11Action(category=hex(0x17))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_dms_resp_action(self, mode):
        action = Dot11Action(category=hex(0x18))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_timing_measurement_req_action(self, mode):
        action = Dot11Action(category=hex(0x19))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_wnm_notification_req_action(self, mode):
        action = Dot11Action(category=hex(0x1A))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_wnm_notification_resp_action(self, mode):
        action = Dot11Action(category=hex(0x1B))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def send_wnm_notify_resp_action(self, mode):
        action = Dot11Action(category=hex(0x1C))
        frame = self.construct_MAC_header(0, self.dest_addr, self.source_addr, self.dest_addr) / action / \
                self.ssid / SUPPORTED_RATES / SUPPL_RATES / STANDARD_POWER_CAPS / STANDARD_SUPP_CHANNELS / STANDARD_RSN / \
                STANDARD_HT_CAPABILITIES / STANDARD_EXT_HT_CAPABILITIES
        return frame

    def fuzz_action(self):
        self.fuzz(self.mode, self.fuzzer_state, self.interface)