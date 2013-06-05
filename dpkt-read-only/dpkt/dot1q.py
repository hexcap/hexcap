# $Id: 8021q.py 23 2013-06-05 14:59:33Z smutt $

"""IEEE 802.1q"""

import dpkt

class Dot1q(dpkt.Packet):
    __hdr__ = (
        ('x2', 'H', 0),
        ('type', 'H', 0)
        )

    # pcp == Priority Code Point(802.1p)
    def _get_pcp(self): return self.x2 >> 13
    def _set_pcp(self, pcp): self.x2 &= 8191 | (pcp << 13)
    pcp = property(_get_pcp, _set_pcp)

    # dei == Drop Eligible Indicator(almost never actually used)
    def _get_dei(self): return (self.x2 >> 12) & 1 
    def _set_dei(self, dei): self.x2 &= 61439 | (de1 << 12)
    dei = property(_get_dei, _set_dei)

    # tag == vlan tag
    def _get_tag(self): return self.x2 & (65535 >> 4)
    def _set_tag(self, tag): self.x2 &= 4095 | tag
    tag = property(_get_tag, _set_tag)

