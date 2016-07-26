


class Branch_block:
	fb = None
	count = None
	function_addr = None
	addr = None
	irsb = None
	insn = []
	def __init__(self,fb,count,addr):
		self.fb = fb
		self.count = count
		self.function_addr = fb.addr
		self.addr = addr


	def set_irsb(self,irsb):
		self.irsb = irsb

	def set_insn(self,insn):
		self.insn = insn