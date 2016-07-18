# -*- coding: utf-8 -*-
try:
    import capstone as _capstone
except ImportError:
    _capstone = None

from error import Error
from Header.Archinfo._arch import _arch

class ArchX86(_arch):
	_backend = None
	bits = 32
	name = "X86"
	vex_arch = "VexArchX86"
	memory_endess = None
	register_endness = None
	sizeof = {'int' : 32, 'long' : 64, 'long long' : 64}



	def __init__(self,endness='Iend_LE',backend=None):
		if _capstone is None:
			raise INSTALLerror("Install the capstone module to use the ArchInfo!")

		if endness != 'Iend_LE':
			raise ArchError("Arch x86 must be little endian")

		super(ArchX86,self).__init__(self.name,bits=self.bits)
		self._backend = backend
		self.memory_endess = endness
		self.register_endness = endness




