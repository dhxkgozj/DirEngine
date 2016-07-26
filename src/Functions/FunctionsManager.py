# -*- coding: utf-8 -*-


import capstone
import pyvex

from Functions.Function import Function
from Functions.Branch import Branch
from Functions.Function_block import Function_block
from Functions.Branch_block import Branch_block
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
				break

			fb = self.fqueue.pop()

			self.handle_function(fb)


	def _initlize_function(self):
		fb = Function_block(self._header._entry,entry_function=True)
		self.fqueue.append(fb)


	def _initlize_branch(self,fb):
		addr = fb.addr + self._header.base_addr
		fb.bqueue_append(Branch_block(fb,0,addr))


	def handle_function(self,fb):

		self._initlize_branch(fb)

		count = 1
		while True:
			if fb.bqueue == []:
				break

			bb = fb.bqueue.pop(0)
			irsb , insn = self.disasmble(bb)
			bb.set_irsb(irsb)
			bb.set_insn(insn)

			self.handle_branch(bb)
			count += 1

	def handle_branch(self,bb):
		irsb = bb.irsb
		import pdb
		pdb.set_trace()
		if irsb.jumpkind == "Ijk_Boring":
			bb.fb.bqueue_append(Branch_block(bb.fb,(bb.count + 1 ),int(str(irsb.next),16)))
		elif irsb.jumpkind == "":
			pass



	def disasmble(self,bb):
		insn = []
		buff = self._header.read_bytes(self._header.read_addr(bb.addr-self._header.base_addr))
		addr = bb.addr
		arch = self._header.arch

		pyvex.set_iropt_level(1)
		irsb = pyvex.IRSB(buff,addr,arch,num_bytes=400,bytes_offset=0,traceflags=0)
		bytestring = buff[:irsb.size]
		cs = arch.capstone
		for cs_insn in cs.disasm(bytestring,addr):
			insn.append(cs_insn)
			print cs_insn.mnemonic, cs_insn.op_str

		return irsb, insn


