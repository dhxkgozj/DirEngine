


class Function_block:
	addr = None
	name = None
	entry_function = False
	bqueue = []
	bqueue_sucess = []
	bqueue_sucess_addr = []
	def __init__(self,addr,entry_function=False):
		self.addr = addr
		self.name = "sub_" + str(addr)
		self.entry_function = entry_function
		self.xref_fb_to = []
		self.xref_fb_from = []


	def bqueue_append(self,bb):
		if not bb.addr in self.bqueue_sucess_addr:
			self.bqueue.append(bb)
			self.bqueue_sucess_addr.append(bb.addr)
			self.bqueue_sucess.append(bb)

	def set_xref_src_fb(self,desc_fb):
		self.xref_fb_from.append(desc_fb)

	def set_xref_desc_fb(self,src_fb):
		self.xref_fb_to.append(src_fb)		