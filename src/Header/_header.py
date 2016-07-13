# -*- coding: utf-8 -*-


class _header(object):
    path = None
    filetype = None
    arch = None
    _entry = None
    alsr = False
    os = None
    base_addr = 0
    def __init__(self,path,filetype):
        self.path = path
        self.filetype = filetype
        self.os = 'windows' if self.filetype == 'pe' else 'unix'

