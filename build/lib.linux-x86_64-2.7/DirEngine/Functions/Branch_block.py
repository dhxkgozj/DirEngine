


class Branch_block:
	fb = None
	count = None
	function_addr = None
	addr = None
	insn = []
	irsb = None
	def __init__(self,fb,count,addr):
		self.fb = fb
		self.count = count
		self.function_addr = fb.addr
		self.addr = addr
		self.xref_bb_to = []
		self.xref_bb_from = []
		self.xref_const_from = []


	def set_irsb(self,irsb):
		self.irsb = irsb

	def set_insn(self,insn):
		self.insn = insn

	def set_xref_src_bb(self,desc_bb):
		self.xref_bb_from.append(desc_bb)

	def set_xref_desc_bb(self,src_bb):
		self.xref_bb_to.append(src_bb)


	def set_xref_const_src_fb(self,desc_fb):
		self.xref_const_from.append(desc_fb)


	def insn_pp(self):
		for i in self.insn:
			print i.mnemonic + " " + i.op_str

