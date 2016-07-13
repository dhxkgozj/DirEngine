# -*- coding: utf-8 -*-
try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None

from error import Error
from header._header import _header

class ELF(_header):
    _backend = None
    _elf = None
    def __init__(self,path,filetype,stream=None,backend=None):
        if ELFFile is None:
            raise CLEError("Install the ELFFile module to use the ELF backend!") 
        super(ELF, self).__init__(path,filetype)
        self._backend = backend
        if stream is None:
            f = open(path,'rb')
            self._elf = ELFFile(f)
        else:
            self._elf = ELFFile(stream)  

        self.arch = self._elf.e_machine
        self._entry = self._elf.header.e_entry

