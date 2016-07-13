# -*- coding: utf-8 -*-
try:
    import pefile
except ImportError:
    pefile = None

from error import Error
from header._header import _header

class PE(_header):
    _backend = None
    _pe = None
    def __init__(self,path,filetype,stream=None,backend=None):
        if pefile is None:
            raise CLEError("Install the pefile module to use the PE backend!")      
        super(PE, self).__init__(path,filetype)
        self._backend = backend
        if stream is None:
            self._pe = pefile.PE(path)
        else:
            self._pe = pefile.PE(data=stream.read())

        self.arch = pefile.MACHINE_TYPE[self._pe.FILE_HEADER.Machine]
        self.base_addr = self._pe.OPTIONAL_HEADER.ImageBase
        self._entry = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint