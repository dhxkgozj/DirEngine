# -*- coding: utf-8 -*-
try:
    import capstone as _capstone
except ImportError:
    _capstone = None
    
from ...error import Error
from ._arch import _arch

class ArchX86(_arch):
    _backend = None
    bits = 32
    name = "X86"
    memory_endess = None
    sizeof = {'int' : 32, 'long' : 64, 'long long' : 64}
    cs_mode = _capstone.CS_MODE_32 + _capstone.CS_MODE_LITTLE_ENDIAN
    cs_arch = _capstone.CS_ARCH_X86


    def __init__(self,endness='Iend_LE',backend=None):
        if _capstone is None:
            raise INSTALLerror("Install the capstone module to use the ArchInfo!")

        if endness != 'Iend_LE':
            raise ArchError("Arch x86 must be little endian")

        super(ArchX86,self).__init__(self.name,bits=self.bits)
        if self.vex_archinfo:
            self.vex_archinfo['x86_cr0'] = 0xFFFFFFFF
        self.vex_arch = "VexArchX86"
        self._backend = backend
        self.memory_endess = endness
        self.register_endness = endness



    register_names = {
        8: 'eax',
        12: 'ecx',
        16: 'edx',
        20: 'ebx',

        24: 'esp',

        28: 'ebp',
        32: 'esi',
        36: 'edi',

        # condition stuff
        40: 'cc_op',
        44: 'cc_dep1',
        48: 'cc_dep2',
        52: 'cc_ndep',

        # this determines which direction SSE instructions go
        56: 'd',

        # separately-stored bits of eflags
        60: 'id',
        64: 'ac',

        68: 'eip',

        # fpu registers
        72: 'st7',
        80: 'st6',
        88: 'st5',
        96: 'st4',
        104: 'st3',
        112: 'st2',
        120: 'st1',
        128: 'st0',

        # fpu tags
        136: 'fpu_t0',
        137: 'fpu_t1',
        138: 'fpu_t2',
        139: 'fpu_t3',
        140: 'fpu_t4',
        141: 'fpu_t5',
        142: 'fpu_t6',
        143: 'fpu_t7',

        # fpu settings
        144: 'fpround',
        148: 'fc3210',
        152: 'ftop',

        # sse
        156: 'sseround',
        160: 'xmm0',
        176: 'xmm1',
        192: 'xmm2',
        208: 'xmm3',
        224: 'xmm4',
        240: 'xmm5',
        256: 'xmm6',
        272: 'xmm7',

        288: 'cs',
        290: 'ds',
        292: 'es',
        294: 'fs',
        296: 'gs',
        298: 'ss',

        304: 'ldt',
        312: 'gdt'
    }

