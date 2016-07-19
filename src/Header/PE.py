# -*- coding: utf-8 -*-
try:
    import pefile
except ImportError:
    pefile = None

from error import Error
from header._header import _header
from header.Archinfo.ArchSelector import ArchSelector

class PE(_header):
    _backend = None
    _pe = None
    def __init__(self,path,filetype,stream=None,backend=None):
        if pefile is None:
            raise CLEError("Install the pefile module to use the PE backend!")      
        super(PE, self).__init__(path,filetype)
        self._backend = backend
        if stream is None:
            f = open(path,'rb')
            self.bin_data = f.read()
            f.close()
            self._pe = pefile.PE(path)
        else:
            stream.seek(0)
            self.bin_data = stream.read()
            stream.seek(0)
            self._pe = pefile.PE(data=stream.read())

        self.arch_str = pefile.MACHINE_TYPE[self._pe.FILE_HEADER.Machine]
        self.base_addr = self._pe.OPTIONAL_HEADER.ImageBase
        self._entry = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint

        self.set_arch(ArchSelector().search(self.arch_str))


    def read_rva_addr(self,addr):
        for section in self._pe.sections:
            if section.contains_rva(addr-self.base_addr): 
                return ((addr-self.base_addr) - section.VirtualAddress + section.PointerToRawData)


    def read_addr(self,addr):
        for section in self._pe.sections:
            if section.contains_rva(addr): 
                return (addr - section.VirtualAddress + section.PointerToRawData)


