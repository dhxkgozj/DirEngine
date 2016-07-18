# -*- coding: utf-8 -*-


class _header(object):
    path = None # file name
    filetype = None # PE,ELF
    arch = None #Archinfo Class
    arch_str = None # x86,arm
    _entry = None # entry point *PE -> this var + base_addr = entry
    alsr = False # aslr enable
    os = None # os type windows,linux
    base_addr = 0 # pe = baseaddr
    endness = "Iend_LE" # endianness
    def __init__(self,path,filetype):
        self.path = path
        self.filetype = filetype
        self.os = 'windows' if self.filetype == 'pe' else 'unix'


    def set_arch(self,arch):
        self.arch = arch