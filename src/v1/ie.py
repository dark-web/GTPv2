"""
Hold GTPv2 Information Element fields
"""
from scapy.fields import *
from scapy.packet import Packet, Raw

IEType = {
    0: "Reserved",
    1: "Cause",
    2: "IMSI",
    3: "RAI",
    4: "TLLI",
    5: "P_TMSI",
    14: "Recovery",
    15: "SelectionMode",
    16: "TEIDI",
    17: "TEICP",
    19: "TeardownInd",
    20: "NSAPI",
    26: "ChargingChrt",
    27: "TraceReference",
    28: "TraceType",
    128: "EndUserAddress",
    131: "AccessPointName",
    132: "ProtocolConfigurationOptions",
    133: "GSNAddress",
    134: "MSInternationalNumber",
    135: "QoS",
    148: "CommonFlags",
    151: "RatType",
    152: "UserLocationInformation",
    153: "MSTimeZone",
    154: "IMEI"
}

IECause = {  0: "Request IMSI",
                 1: "Request IMEI",
                 2: "Request IMSI and IMEI",
                 3: "No identity needed",
                 4: "MS Refuses",
                 5: "MS is not GPRS Responding",
               128: "Request accepted",
               129: "New PDP type due to network preference",
               130: "New PDP type due to single address bearer only",
               192: "Non-existent",
               193: "Invalid message format",
               194: "IMSI not known",
               195: "MS is GPRS Detached",
               196: "MS is not GPRS Responding",
               197: "MS Refuses",
               198: "Version not supported",
               199: "No resources available",
               200: "Service not supported",
               201: "Mandatory IE incorrect",
               202: "Mandatory IE missing",
               203: "Optional IE incorrect",
               204: "System failure",
               205: "Roaming restriction",
               206: "P-TMSI Signature mismatch",
               207: "GPRS connection suspended",
               208: "Authentication failure",
               209: "User authentication failed",
               210: "Context not found",
               211: "All dynamic PDP addresses are occupied",
               212: "No memory is available",
               213: "Reallocation failure",
               214: "Unknown mandatory extension header",
               215: "Semantic error in the TFT operation",
               216: "Syntactic error in TFT operation",
               217: "Semantic errors in packet filter(s)",
               218: "Syntactic errors in packet filter(s)",
               219: "Missing or unknown APN",
               220: "Unknown PDP address or PDP type",
               221: "PDP context without TFT already activated",
               222: "APN access denied : no subscription",
               223: "APN Restriction type incompatibility with currently active PDP Contexts",
               224: "MS MBMS Capabilities Insufficient",
               225: "Invalid Correlation : ID",
               226: "MBMS Bearer Context Superseded",
               227: "Bearer Control Mode violation",
               228: "Collision with network initiated request" }


class IERecovery(Packet):
    """
    Hold a GTPv1 Recovery IE
    """
    name = "Recovery IE"
    fields_desc = [
        ByteEnumField("type", 14, IEType),
        ByteField("restart_counter", 0)
    ]

    def extract_padding(self, s):
        return "", s


class IETEIDI(Packet):
    """
    A Tunnel Endpoint Identifier Data I element
    """
    name = "Tunnel Endpoint Identifier Data I"
    fields_desc = [
        ByteEnumField("type", 16, IEType),
        IntField("TEIDI", 0)
    ]

    def extract_padding(self, s):
        return "", s



class IEGTP_U_Peer_Address(Packet):
    """
    A GTP v1 GTP-U Peer Address
    """
    name = "GTP-U Peer Address"
    fields_desc = [
        ByteEnumField("type", 133, IEType),
        ShortField("length", 4),
        ConditionalField(IPField("v4_addr", '127.0.0.1'), lambda pkt: pkt.length == 4),
        ConditionalField(BitField("v6_addr", 0, 128), lambda pkt: pkt.length == 16)
    ]

    def extract_padding(self, s):
        return "", s        # doing this stops payload processing as these are no layers but fields in a layer

class IENotImplemented(Packet):
    name = "IE not implemented"
    fields_desc = [
        ByteEnumField("ietype", 0, IEType),
        ShortField("length", None),
        StrLenField("data", "", length_from=lambda x: x.length)
    ]


IETypeCls = {
    14: IERecovery,
    16: IETEIDI,
    133: IEGTP_U_Peer_Address
}


def IE_Lookup(pkt):
    if len(pkt) < 1:
        return Raw(pkt)
    type = ord(pkt[0])  # type is held in first byte of an IE packet

    cls = IETypeCls.get(type, Raw)

    if cls == Raw or (type > 133 and type < 255):
        cls = IENotImplemented  # We haven't implemented this one yet

    return cls(pkt)  # Return an instance of the correct Packet
