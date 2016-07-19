


class Function_block:
	addr = None
	entry_function = False
	def __init__(self,addr,entry_function=False):
		self.addr = addr
		self.entry_function = entry_function