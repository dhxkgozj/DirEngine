# -*- coding: utf-8 -*-



class Decompiler:
	CF = None
	def __init__(self,CF):
		self.CF = CF 

	def Decompile(self,fb):
		fb_irsb = []
		for block in fb.bqueue_sucess:
			fb_irsb.append(block.irsb)

		self._step1_varOptim1(fb,fb_irsb)


	def _step1_varOptim1(self,fb,fb_irsb):
		pass