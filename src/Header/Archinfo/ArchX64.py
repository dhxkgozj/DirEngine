# -*- coding: utf-8 -*-
try:
    import capstone as _capstone
except ImportError:
    _capstone = None
    
from error import Error
from Header.Archinfo._arch import _arch

class ArchX64(_arch):
    _backend = None
    bits = 64
    name = "X64"
    memory_endess = None
    sizeof = {'int' : 32, 'long' : 64, 'long long' : 64}
    cs_arch = _capstone.CS_ARCH_X86
    cs_mode = _capstone.CS_MODE_64 + _capstone.CS_MODE_LITTLE_ENDIAN


    def __init__(self,endness='Iend_LE',backend=None):
        if _capstone is None:
            raise INSTALLerror("Install the capstone module to use the ArchInfo!")

        if endness != 'Iend_LE':
            raise ArchError("Arch x64 must be little endian")

        super(ArchX64,self).__init__(self.name,bits=self.bits)
        self.vex_arch = "VexArchAMD64"
        self._backend = backend
        self.memory_endess = endness
        self.register_endness = endness



    register_names = {
        0: 'host_evc_failaddr',
        8: 'host_evc_counter',
        12: 'pad0',
        16: 'rax',
        24: 'rcx',
        32: 'rdx',
        40: 'rbx',
        48: 'rsp',
        56: 'rbp',
        64: 'rsi',
        72: 'rdi',
        80: 'r8',
        88: 'r9',
        96: 'r10',
        104: 'r11',
        112: 'r12',
        120: 'r13',
        128: 'r14',
        136: 'r15',
        144: 'cc_op',
        152: 'cc_dep1',
        160: 'cc_dep2',
        168: 'cc_ndep',
        176: 'dflag',
        184: 'rip',
        192: 'acflag',
        200: 'idflag',
        208: 'fs_const',
        216: 'sseround',
        224: 'ymm0',
        256: 'ymm1',
        288: 'ymm2',
        320: 'ymm3',
        352: 'ymm4',
        384: 'ymm5',
        416: 'ymm6',
        448: 'ymm7',
        480: 'ymm8',
        512: 'ymm9',
        544: 'ymm10',
        576: 'ymm11',
        608: 'ymm12',
        640: 'ymm13',
        672: 'ymm14',
        704: 'ymm15',
        736: 'ymm16',
        768: 'ftop',
        772: 'pad1',
        776: 'st0',
        784: 'st1',
        792: 'st2',
        800: 'st3',
        808: 'st4',
        816: 'st5',
        824: 'st6',
        832: 'st7',
        840: 'tag0',
        841: 'tag1',
        842: 'tag2',
        843: 'tag3',
        844: 'tag4',
        845: 'tag5',
        846: 'tag6',
        847: 'tag7',
        848: 'fpround',
        856: 'fc3210',
        864: 'emnote',
        868: 'pad2',
        872: 'cmstart',
        880: 'cmlen',
        888: 'nraddr',
        896: 'sc_class',
        904: 'gs_const',
        912: 'ip_at_syscall',
        920: 'pad3'
    }

