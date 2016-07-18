# -*- coding: utf-8 -*-

from Functions.Function import Function
from Functions.Branch import Branch

class FunctionsManager:
	_header = None
	_options = {}
	functions = []
	def __init__(self,header,options):
		self._header = header
		self._options = options


	def analyze(self):
		self.functions = []



class CodeFlowManager:

	def __init__(self):
		pass
