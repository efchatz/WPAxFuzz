from scapy.fields import ByteEnumField
from scapy.packet import Packet

class Dot11Block(Packet):
    name = "802.11 Block Action"
    fields_desc = [
        ByteEnumField("action", 0x00, {
            0x00: "ADDBA Request",
            0x01: "ADDBA Response",
            0x02: "DELBA"
        })
    ]