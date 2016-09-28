# -*- coding: utf-8 -*-

import struct,hashlib,sys

from ..error import Error
from .PE import PE
from .ELF import ELF

class Backend:
    path = None
    load_options = {}
    filetype = None
    def __init__(self,path,load_options):
        self.path = path
        self.load_options

    def Loader(self):
        _header = None
        if hasattr(self.path, 'seek') and hasattr(self.path, 'read'):
            self.path.seek(0)
            stream = self.path
        else:
            stream = open(self.path, 'rb')
        filetype = self.identify_filetype(stream)
        if(filetype == "pe"):
            _header = PE(self.path,filetype,stream=stream)
            
        elif(filetype == "elf"):
            _header = ELF(self.path,filetype,stream=stream)

        return _header

    def identify_filetype(self,stream):
        identstring = stream.read(0x1000)
        stream.seek(0)

        if identstring.startswith('\x7fELF'):
            return 'elf'
        elif identstring.startswith('MZ') and len(identstring) > 0x40:
            peptr = struct.unpack('I', identstring[0x3c:0x40])[0]
            if peptr < len(identstring) and identstring[peptr:peptr+4] == 'PE\0\0':
                return 'pe'
        elif identstring.startswith('\xfe\xed\xfa\xce') or \
             identstring.startswith('\xfe\xed\xfa\xcf') or \
             identstring.startswith('\xce\xfa\xed\xfe') or \
             identstring.startswith('\xcf\xfa\xed\xfe'):
            return 'mach-o'
        elif identstring.startswith('\x7fCGC'):
            return 'cgc'
        return 'unknown'        
