#-*- coding: utf-8 -*-
import threading, sys, platform,os,json
sys.path.append("./")

from Header.Backend import Backend
from Functions.FunctionsManager import FunctionsManager

class DirEngine:
    path = None
    arch = None
    load_options = {}
    def __init__(self,path,arch=None,defalut_analysis_mode=None,load_options=None):
        self.path = path
        self.arch = arch

        if load_options is None:
            load_options = {}
        self.load_options = load_options


        if path == None:
            raise Exception("Path is None")

        elif not isinstance(path, (unicode, str)) or not os.path.exists(path) or not os.path.isfile(path):
            raise Exception("Not a valid binary file: %s" % repr(path))


    def Analysis(self):
        if(self.arch != None):
            pass
        backend = Backend(self.path,self.load_options)
        header = backend.Loader()
        manager = FunctionsManager(header,self.load_options)
        manager.analyze()
        print header.endness
        print header.os
        print header
        print header.arch

        del backend


        

if __name__ == "__main__":
    c  = DirEngine('taint.exe').Analysis()
    a  = DirEngine('notepad.exe').Analysis()
    b  = DirEngine('/bin/sh').Analysis()
