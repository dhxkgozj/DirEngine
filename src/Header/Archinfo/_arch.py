# -*- coding: utf-8 -*-

class _arch(object):
	name = None
	bits = None


	def __init__(self,name,bits=32):
		self.name = name
		self.bits = bits