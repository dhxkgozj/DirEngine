# -*- coding: utf-8 -*-

import os

class _header(object):
    filename = None # file name
    path = None # file path
    filetype = None # PE,ELF
    arch = None #Archinfo Class
    arch_str = None # x86,arm
    _entry = None # entry point *PE -> this var + base_addr = entry
    alsr = False # aslr enable
    os = None # os type windows,linux
    base_addr = 0 # pe = baseaddr
    endness = "Iend_LE" # endianness
    bin_data = None # Binary Data
    fileMd5 = None
    fileSha1 = None
    fileSha256 = None
    fileSha512 = None
    def __init__(self,path,filetype):
        self.path = path
        self.filename = os.path.basename(self.path)
        self.filetype = filetype
        self.os = 'windows' if self.filetype == 'pe' else 'unix'


    def set_arch(self,arch):
        self.arch = arch


    def set_aslr(self,aslr):
        self.aslr = aslr

    def read_bytes(self,offset,size=100):
        return self.bin_data[offset:offset+size]


    def read_addr(self,addr):
        raise NotImplementedError("read_addr is not implemented.") 

    def read_rva_to_addr(self,rva):
        raise NotImplementedError("read_rva_to_addr is not implemented.") 


    @property
    def get_md5(self):
        return self.fileMd5
    @property
    def get_sha1(self):
        return self.fileSha1
    @property
    def get_sha256(self):
        return self.fileSha256
    @property
    def get_sha512(self):
        return self.fileSha512