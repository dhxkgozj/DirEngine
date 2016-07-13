# -*- coding: utf-8 -*-

import struct

from error import Error
from Header.PE import PE
from Header.ELF import ELF

class Backend:
    path = None
    load_options = {}
    filetype = None
    def __init__(self,path,load_options):
        self.path = path
        self.load_options

    def Loader(self):
        if hasattr(self.path, 'seek') and hasattr(self.path, 'read'):
            self.path.seek(0)
            stream = self.path
        else:
            stream = open(self.path, 'rb')

        self.filetype = self.identify_filetype(stream)

        if(self.filetype == "pe"):
            _header = PE(self.path,self.filetype,stream=stream)

        elif(self.filetype == "elf"):
            _header = ELF(self)
        
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