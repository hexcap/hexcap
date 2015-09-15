# -*- coding: utf-8 -*-
"""ATA over Ethernet Protocol."""

import struct
import dpkt
from decorators import deprecated


class AOE(dpkt.Packet):
    __hdr__ = (
        ('ver_fl', 'B', 0x10),
        ('err', 'B', 0),
        ('maj', 'H', 0),
        ('min', 'B', 0),
        ('cmd', 'B', 0),
        ('tag', 'I', 0),
    )
    _cmdsw = {}

    @property
    def ver(self): return self.ver_fl >> 4

    @ver.setter
    def ver(self, ver): self.ver_fl = (ver << 4) | (self.ver_fl & 0xf)

    @property
    def fl(self): return self.ver_fl & 0xf

    @fl.setter
    def fl(self, fl): self.ver_fl = (self.ver_fl & 0xf0) | fl

    @classmethod
    def set_cmd(cls, cmd, pktclass):
        cls._cmdsw[cmd] = pktclass

    @classmethod
    def get_cmd(cls, cmd):
        return cls._cmdsw[cmd]

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        try:
            self.data = self._cmdsw[self.cmd](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, struct.error, dpkt.UnpackError):
            pass

    def pack_hdr(self):
        try:
            return dpkt.Packet.pack_hdr(self)
        except struct.error, e:
            raise dpkt.PackError(str(e))

    # Deprecated methods, will be removed in the future
    # =================================================
    @deprecated('ver')
    def _get_ver(self): return self.ver

    @deprecated('ver')
    def _set_ver(self, ver): self.ver = ver

    @deprecated('fl')
    def _get_fl(self): return self.fl

    @deprecated('fl')
    def _set_fl(self, fl): self.fl = fl
    # =================================================



AOE_CMD_ATA = 0
AOE_CMD_CFG = 1
AOE_FLAG_RSP = 1 << 3


def __load_cmds():
    prefix = 'AOE_CMD_'
    g = globals()
    for k, v in g.iteritems():
        if k.startswith(prefix):
            name = 'aoe' + k[len(prefix):].lower()
            try:
                mod = __import__(name, g, level=1)
                AOE.set_cmd(v, getattr(mod, name.upper()))
            except (ImportError, AttributeError):
                continue


if not AOE._cmdsw:
    __load_cmds()
