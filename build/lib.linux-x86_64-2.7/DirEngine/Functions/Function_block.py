


class Function_block:
	addr = None
	name = None
	entry_function = False
	const_jump = False
	bqueue = []
	bqueue_sucess = []
	bqueue_sucess_addr = []
	def __init__(self,addr,const_jump=False,entry_function=False):
		self.addr = addr
		self.name = "sub_" + str(hex(addr))
		self.entry_function = entry_function
		self.xref_fb_to = []
		self.xref_fb_from = []
		self.xref_const_to = []
		self.const_jump = const_jump



	def bqueue_append(self,bb):
		if not bb.addr in self.bqueue_sucess_addr:
			self.bqueue.append(bb)
			self.bqueue_sucess_addr.append(bb.addr)
			self.bqueue_sucess.append(bb)

	def set_xref_src_fb(self,desc_fb):
		self.xref_fb_from.append(desc_fb.addr)

	def set_xref_desc_fb(self,src_fb):
		self.xref_fb_to.append(src_fb.addr)

	def set_xref_const_desc_fb(self,src_bb):
		self.xref_const_to.append(src_bb.addr)