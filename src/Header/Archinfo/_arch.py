# -*- coding: utf-8 -*-

try:
    import pyvex as _pyvex
except ImportError:
    _pyvex = None


class _arch(object):
    name = None
    bits = None
    vex_archinfo = None
    vex_arch = None
    register_endness = None
    memory_endness = None
    register_names = { }
    def __init__(self,name,bits=32):
        self.name = name
        self.bits = bits
        self.vex_archinfo = _pyvex.default_vex_archinfo()

        if self.register_endness == "Iend_BE":
            if self.vex_archinfo:
                self.vex_archinfo['endness'] = _pyvex.vex_endness_from_string('VexEndnessBE')
            self.memory_endness = 'Iend_BE'
            self.cs_mode -= _capstone.CS_MODE_LITTLE_ENDIAN
            self.cs_mode += _capstone.CS_MODE_BIG_ENDIAN
            self.ret_instruction = reverse_ends(self.ret_instruction)
            self.nop_instruction = reverse_ends(self.nop_instruction)

    def translate_register_name(self, offset):
        try:
            return self.register_names[offset]
        except KeyError:
            return str(offset)            