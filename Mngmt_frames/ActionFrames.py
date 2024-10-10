from scapy.fields import ByteEnumField, BitField, NBytesField, PacketField
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


class Dot11BlockAckParameterSet(Packet):
    name = "Block Ack Parameter Set"
    fields_desc = [
        BitField("a_msdu_supported", 1, 1),
        BitField("block_ack_policy", 1, 1),
        BitField("tid", 0, 4),
        BitField("buffer_size", 0, 10)
    ]


class Dot11BlockAckTimeoutValue(Packet):
    name = "Block Ack Timeout Value"
    fields_desc = [
        NBytesField("block_ack_timeout_value", 0, 2)
    ]


class Dot11BlockAckStartingSequenceControl(Packet):
    name = "Block Ack Starting Sequence Control"
    fields_desc = [
        BitField("fragment_number", 0, 4),
        BitField("starting_sequence_number", 0, 12)
    ]


class Dot11StatusCode(Packet):
    name = "Status Code"
    fields_desc = [
        NBytesField("status_code", 0, 2)
    ]


class Dot11DELBAParameters(Packet):
    name = "DELBA Parameters"
    fields_desc = [
        BitField("initiator", 1, 1),
        BitField("tid", 0, 4)
    ]


class Dot11ReasonCode(Packet):
    name = "Reason Code"
    fields_desc = [
        NBytesField("reason_code", 0, 2)
    ]


class Dot11ADDBARequest(Packet):
    name = "ADDBA Request"
    fields_desc = [
        PacketField("block_ack_parameter_set", Dot11BlockAckParameterSet(), Dot11BlockAckParameterSet),
        PacketField("block_ack_timeout_value", Dot11BlockAckTimeoutValue(), Dot11BlockAckTimeoutValue),
        PacketField("block_ack_starting_sequence_control", Dot11BlockAckStartingSequenceControl(),
                    Dot11BlockAckStartingSequenceControl)
    ]


class Dot11ADDBAResponse(Packet):
    name = "ADDBA Response"
    fields_desc = [
        PacketField("status_code", Dot11StatusCode(), Dot11StatusCode),
        PacketField("block_ack_parameter_set", Dot11BlockAckParameterSet(), Dot11BlockAckParameterSet),
        PacketField("block_ack_timeout_value", Dot11BlockAckTimeoutValue(), Dot11BlockAckTimeoutValue)
    ]


class Dot11DELBA(Packet):
    name = "DELBA"
    fields_desc = [
        PacketField("parameters", Dot11DELBAParameters(), Dot11DELBAParameters),
        PacketField("reason_code", Dot11ReasonCode(), Dot11ReasonCode)
    ]
