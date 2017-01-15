"""
Hold GTPv2 Information Element fields
"""
from scapy.fields import *
from scapy.packet import Packet, Raw

IEType = {
   0: "Reserved",
   1: "International Mobile Subscriber Identity (IMSI)",
   2: "Cause",
   3: "Recovery (Restart Counter)",
   # 4 to 34 Reserved for S101 interface
   # 35 to 50 Reserved for S121 interface
   51: "STN-SR",
   # 52 to 70 Reserved for Sv interface
   71: "Access Point Name (APN)",
   72: "Aggregate Maximum Bit Rate (AMBR)",
   73: "EPS Bearer ID (EBI)",
   74: "IP Address",
   75: "Mobile Equipment Identity (MEI)",
   76: "MSISDN",
   77: "Indication",
   78: "Protocol Configuration Options (PCO)",
   79: "PDN Address Allocation (PAA)",
   80: "Bearer Level Quality of Service (Bearer QoS)",
   81: "Flow Quality of Service (Flow QoS)",
   82: "RAT Type",
   83: "Serving Network",
   84: "EPS Bearer Level Traffic Flow Template (Bearer TFT)",
   85: "Traffic Aggregation Description (TAD)",
   86: "User Location Information (ULI)",
   87: "Fully Qualified Tunnel Endpoint Identifier (F-TEID)",
   88: "TMSI",
   89: "Global CN-Id",
   90: "S103 PDN Data Forwarding Info (S103PDF)",
   91: "S1-U Data Forwarding Info (S1UDF)",
   92: "Delay Value",
   93: "Bearer Context ",
   94: "Charging ID",
   95: "Charging Characteristics",
   96: "Trace Information",
   97: "Bearer Flags",
   98: "Reserved",
   99: "PDN Type",
   100: "Procedure Transaction ID",
   101: "Reserved",
   102: "Reserved",
   103: "MM Context (GSM Key and Triplets)",
   104: "MM Context (UMTS Key, Used Cipher and Quintuplets)",
   105: "MM Context (GSM Key, Used Cipher and Quintuplets)",
   106: "MM Context (UMTS Key and Quintuplets)",
   107: "MM Context (EPS Security Context, Quadruplets and Quintuplets)",
   108: "MM Context (UMTS Key, Quadruplets and Quintuplets)",
   109: "PDN Connection",
   110: "PDU Numbers",
   111: "P-TMSI",
   112: "P-TMSI Signature",
   113: "Hop Counter",
   114: "UE Time Zone",
   115: "Trace Reference",
   116: "Complete Request Message",
   117: "GUTI",
   118: "F-Container",
   119: "F-Cause",
   120: "PLMN ID",
   121: "Target Identification",
   122: "Reserved ",
   123: "Packet Flow ID ",
   124: "RAB Context ",
   125: "Source RNC PDCP Context Info",
   126: "UDP Source Port Number",
   127: "APN Restriction",
   128: "Selection Mode",
   129: "Source Identification",
   130: "Reserved",
   131: "Change Reporting Action",
   132: "Fully Qualified PDN Connection Set Identifier (FQ-CSID)",
   133: "Channel needed",
   134: "eMLPP Priority",
   135: "Node Type",
   136: "Fully Qualified Domain Name (FQDN)",
   137: "Transaction Identifier (TI)",
   138: "MBMS Session Duration",
   139: "MBMS Service Area",
   140: "MBMS Session Identifier",
   141: "MBMS Flow Identifier",
   142: "MBMS IP Multicast Distribution",
   143: "MBMS Distribution Acknowledge",
   144: "RFSP Index",
   145: "User CSG Information (UCI)",
   146: "CSG Information Reporting Action",
   147: "CSG ID",
   148: "CSG Membership Indication (CMI)",
   149: "Service indicator",
   150: "Detach Type",
   151: "Local Distiguished Name (LDN)",
   152: "Node Features",
   153: "MBMS Time to Data Transfer",
   154: "Throttling",
   155: "Allocation/Retention Priority (ARP)",
   156: "EPC Timer",
   157: "Signalling Priority Indication",
   158: "Temporary Mobile Group Identity (TMGI)",
   159: "Additional MM context for SRVCC",
   160: "Additional flags for SRVCC",
   161: "Reserved",
   162: "MDT Configuration",
   163: "Additional Protocol Configuration Options (APCO)",
   164: "Absolute Time of MBMS Data Transfer",
   165: "H(e)NB Information Reporting ",
   166: "IPv4 Configuration Parameters (IP4CP)",
   167: "Change to Report Flags ",
   168: "Action Indication",
   169: "TWAN Identifier",
   170: "ULI Timestamp",
   171: "MBMS Flags",
   172: "RAN/NAS Cause",
   173: "CN Operator Selection Entity",
   174: "Trusted WLAN Mode Indication",
   175: "Node Number",
   176: "Node Identifier",
   177: "Presence Reporting Area Action",
   178: "Presence Reporting Area Information",
   179: "TWAN Identifier Timestamp",
   180: "Overload Control Information",
   181: "Load Control Information",
   182: "Metric",
   183: "Sequence Number",
   184: "APN and Relative Capacity",
   185: "WLAN Offloadability Indication",
   # 186 to 254 Spare. For future use.
   255: "Private Extension",
 }






class IERecovery(Packet):
    """
    Packet that holds a Recovery counter Information Element (See 3GPP TS 29.274 V12.13.0 Section 8.5)
    """

    name = "Recovery (Restart Counter)"
    fields_desc = [
        ByteEnumField("ie_type", 3, IEType),
        ShortField("length", 1),
        BitField("spare", 0, 4),
        BitField("instance", 0, 4),
        ByteField("counter", 0)
    ]


class IENotImplemented(Packet):
    name = "IE not implemented"
    fields_desc = [
        ByteEnumField("ietype", 0, IEType),
        ShortField("length",  None),
        StrLenField("data", "", length_from=lambda x: x.length)
    ]


IETypeCls = {
    3: IERecovery
}


def IE_Lookup(pkt):
    if len(pkt) < 1:
        return Raw(pkt)
    type = ord(pkt[0])    # type is held in first byte of an IE packet

    cls = IETypeCls.get(type, Raw)

    if cls == Raw:
        cls = IENotImplemented      # We haven't implemented this one yet

    return cls(pkt)             # Return an instance of the correct Packet

