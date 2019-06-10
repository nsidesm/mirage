from scapy.all import *

'''
This module contains some scapy definitions for communicating with an HCI device.
'''
#split_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Advertising_Data)
#split_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Scan_Response_Data)

class HCI_Cmd_LE_Rand(Packet):
	name = "HCI Command LE Rand"
	fields_desc = []	

class HCI_LE_Meta_Enhanced_Connection_Complete(Packet):
    name = "Enhanced Connection Complete"
    fields_desc = [ByteEnumField("status", 0, {0: "success"}),
                   LEShortField("handle", 0),
                   ByteEnumField("role", 0, {0: "master"}),
                   ByteEnumField("patype", 0, {0: "public", 1: "random"}),
                   LEMACField("paddr", None),
                   LEMACField("localresolvprivaddr", None),
                   LEMACField("peerresolvprivaddr", None),
                   LEShortField("interval", 54),
                   LEShortField("latency", 0),
                   LEShortField("supervision", 42),
                   XByteField("clock_latency", 5), ]

    def answers(self, other):
        if HCI_Cmd_LE_Create_Connection not in other:
            return False

        return (other[HCI_Cmd_LE_Create_Connection].patype == self.patype and
                other[HCI_Cmd_LE_Create_Connection].paddr == self.paddr)


class New_HCI_Cmd_LE_Set_Advertising_Data(Packet):
    name = "LE Set Advertising Data"
    fields_desc = [FieldLenField("len", None, length_of="data", fmt="B"),
                   PadField(
                       PacketListField("data", [], EIR_Hdr,
                                       length_from=lambda pkt:pkt.len),
			align=31, padwith=b"\0"), ]

class New_HCI_Cmd_LE_Set_Scan_Response_Data(Packet):
    name = "LE Set Scan Response Data"
    fields_desc = [FieldLenField("len", None, length_of="data", fmt="B"),
                   StrLenField("data", "", length_from=lambda pkt:pkt.len), ]


class SM_Security_Request(Packet):
    name = "Security Request"
    fields_desc = [BitField("authentication", 0, 8)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Rand, opcode=0x2018)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Enhanced_Connection_Complete, event = 0xa)
bind_layers(SM_Hdr, SM_Security_Request, sm_command=0xb)

bind_layers(HCI_Command_Hdr, New_HCI_Cmd_LE_Set_Advertising_Data, opcode=0x2008)
bind_layers(HCI_Command_Hdr, New_HCI_Cmd_LE_Set_Scan_Response_Data, opcode=0x2009)
