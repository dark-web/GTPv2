#! /usr/bin/env python

"""
Implement GTPv1 User plane in a way that can detect responses (other versions don't seem able to do this
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import IP, UDP
from scapy.layers.sctp import SCTP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import *

from ie import *
import logging
import time
import sys

logging.getLogger("scapy").setLevel(1)      # get warnings for now

GTPv1MessageTypes = {   1: "echo_request",
                     2: "echo_response",
                    16: "create_pdp_context_req",
                    17: "create_pdp_context_res",
                    20: "delete_pdp_context_req",
                    21: "delete_pdp_context_res",
                    26: "error_indication",
                    27: "pdu_notification_req",
                   255: "gtp_t_pdu" }





Selection_Mode = { 11111100: "MS or APN",
                   11111101: "MS",
                   11111110: "NET",
                   11111111: "FutureUse" }

TeardownInd_value = { 254: "False",
                      255: "True" }


class GTPv1UserHeader(Packet):
    """
    The GTP v1 User plane header
    """
    name = "GTPv1 User Header"

    fields_desc = [
        BitField("version", 1, 3),
        BitField("PT", 1, 1),
        BitField("spare", 0, 1),
        BitField("E", 0, 1),
        BitField("S", 0, 1),
        BitField("PN", 0, 1),
        ByteEnumField("message_type", None, GTPv1MessageTypes),
        ShortField("length", None),
        IntField("TEID", 0),
        ConditionalField(ShortField("seq", 0), lambda pkt: pkt.S == 1 or pkt.PN == 1 or pkt.E == 1),
        ConditionalField(ByteField("npdu", 0), lambda pkt: pkt.S == 1 or pkt.PN == 1 or pkt.E == 1),
        ConditionalField(ByteField("next_extension_type", 0), lambda pkt: pkt.S == 1 or pkt.PN == 1 or pkt.E == 1),
    ]

    def post_build(self, pkt, pay):
        pkt += pay
        if self.length is None:
            warning("Setting Length")
            l = len(pkt) - 8  # message len of gtpv1 is length of whole minus the mandatory parts of the header (first 8 octets)
            pkt = pkt[:2] + struct.pack("!H", l) + pkt[4:]
        return pkt

    def answers(self, other):
        """
        Does this answer another
        :param other:
        :return:
        """
        if self.message_type == 2:  # echo response
            return isinstance(other, GTPv1UserHeader) and \
                          self.version == other.version and \
                          other.message_type == 1
        else:
            return isinstance(other, GTPv1UserHeader) and \
                          self.version == other.version and \
                          self.payload.answers(other.payload)


class GTPEchoResponse(Packet):
    """
        A GTPv1 echo response -Message Type 2

    """
    name = "GTPv1 Echo Response"

    fields_desc = [
        PacketListField("information_elements", [IERecovery()], IE_Lookup)
    ]

    def answers(self, other):
        # print self.summary()
        print type(other)
        return False


bind_layers(UDP, GTPv1UserHeader, {'dport': 2152})

bind_layers(GTPv1UserHeader, IP, {'message_type': 255})
bind_layers(GTPv1UserHeader, GTPEchoResponse, {'message_type': 2})



if __name__ == "__main__":

    tstPkt = IP(dst=sys.argv[1])/UDP(sport=2152)/GTPv1UserHeader(message_type=1)
    print "Sending..." + tstPkt.summary()
    ans, unans = sr(tstPkt)