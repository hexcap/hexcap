import struct
import dpkt
import ethernet

class IEEE8021Q(ethernet.Ethernet):
    __hdr__ = (
        ('vlan', 'H', 0),
        ('type', 'H', ethernet.ETH_TYPE_IP)
        )

    def unpack(self, buf):
        super(IEEE8021Q, self).unpack(buf)

        self.vlan_id = self.vlan & 0x0fff
        self.pcp     = self.vlan & 0xe000
        self.dei     = self.vlan & 0x1000

    def pack_hdr(self):
        if getattr(self, 'vlan_id', None) is not None:
            self.vlan = (self.vlan & 0xf000 ) | (self.vlan_id & 0x0fff)
        if getattr(self, 'pcp', None) is not None:
            self.vlan = (self.vlan & 0x1fff ) | (self.pcp & 0xe000)
        if getattr(self, 'dei', None) is not None:
            self.vlan = (self.vlan & 0xefff ) | (self.dei & 0x1000)

        return super(IEEE8021Q, self).pack_hdr()
        
