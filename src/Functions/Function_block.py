


class Function_block:
	addr = None
	entry_function = False
	bqueue = []
	bqueue_sucess = []
	def __init__(self,addr,entry_function=False):
		self.addr = addr
		self.entry_function = entry_function


	def bqueue_append(self,bb):
		if not bb.addr in self.bqueue_sucess:
			self.bqueue.append(bb)
			self.bqueue_sucess.append(bb.addr)