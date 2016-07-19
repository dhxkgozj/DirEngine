# -*- coding: utf-8 -*-


import capstone
import pyvex

from Functions.Function import Function
from Functions.Branch import Branch
from Functions.Function_block import Function_block

class FunctionsManager:
	_header = None
	_options = {}
	functions = []
	def __init__(self,header,options):
		self._header = header
		self._options = options


	def analyze(self):
		self.functions = []
		CodeFlowManager(self).analyze()



class CodeFlowManager:
	_manager = None
	_header = None
	fqueue = []
	def __init__(self,manager):
		self._manager = manager
		self._header = self._manager._header
		self.fqueue = []

	def analyze(self):

		self._initlize_function()

		while True:
			if self.fqueue == []:
				pass

			fb = self.fqueue.pop()

			self.handle_function(fb)


	def _initlize_function(self):
		fb = Function_block(self._header._entry,entry_function=True)
		self.fqueue.append(fb)


	def handle_function(self,fb):

		self.disasmble(fb)


	def disasmble(self,fb):
		buff = self._header.read_bytes(self._header.read_addr(fb.addr))
		addr = fb.addr + self._header.base_addr
		arch = self._header.arch
		irsb = pyvex.IRSB(buff,addr,arch,num_bytes=400,bytes_offset=0,traceflags=0)
		print irsb.size
