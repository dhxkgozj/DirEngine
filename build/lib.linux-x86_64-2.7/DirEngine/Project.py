#-*- coding: utf-8 -*-
import threading, sys, platform,os,json

from .Header import Backend
from .Functions.FunctionsManager import FunctionsManager

class Project:
    # 내부적으로 쓰임
    filename = None
    _Analyzer = None # 상위 호출 클래스
    _arch = None
    _load_options = {}
    ##################################
    header = None # 헤더 객체
    fm = None # Function_Manager

    def __init__(self,filename,Analyzer=None,sig_bit=False,arch=None,load_options=None):
        self.filename = filename
        self.Analyzer = Analyzer
        self._arch = arch

        if load_options is None:
            load_options = {}
        self._load_options = load_options

        if filename == None:
            raise Exception("File is None")

        elif not isinstance(filename, (unicode, str)) or not os.path.exists(filename) or not os.path.isfile(filename):
            raise Exception("Not a valid binary file: %s" % repr(filename))


        backend = Backend(self.filename,self._load_options)
        self.header = backend.Loader()
        del backend
    def Analysis(self):
        if(self.header == None):
            return False
            
        self.fm = FunctionsManager(self.header,self._load_options)
        self.fm.analyze()
        '''
        print hex(ord(header.read_bytes(header.read_addr(header._entry))[0]))
        print hex(header._entry)
        print header.os
        print header
        print header.arch
        '''


        

if __name__ == "__main__":
    #c  = DirEngine('taint.exe').Analysis()
    a  = Project('notepad.exe').Analysis()
    #b  = DirEngine('/bin/sh').Analysis()
