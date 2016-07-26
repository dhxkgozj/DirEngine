# -*- coding: utf-8 -*-

from error import Error
from Header.Archinfo.ArchARM32 import ArchARM32
from Header.Archinfo.ArchARM64 import ArchARM64
from Header.Archinfo.ArchMIPS32 import ArchMIPS32
from Header.Archinfo.ArchMIPS64 import ArchMIPS64
from Header.Archinfo.ArchPPC32 import ArchPPC32
from Header.Archinfo.ArchPPC64 import ArchPPC64
from Header.Archinfo.ArchX86 import ArchX86
from Header.Archinfo.ArchX64 import ArchX64


class ArchSelector:
    def __init__(self):
        pass

    def search(self,ident,endness='',bits=''):
        if bits == 64 or (isinstance(bits, str) and '64' in bits):
            bits = 64
        else:
            bits = 32

        endness = endness.lower()
        endness_unsure = False
        if 'lit' in endness:
            endness = 'Iend_LE'
        elif 'big' in endness:
            endness = 'Iend_BE'
        elif 'lsb' in endness:
            endness = 'Iend_LE'
        elif 'msb' in endness:
            endness = 'Iend_BE'
        elif 'le' in endness:
            endness = 'Iend_LE'
        elif 'be' in endness:
            endness = 'Iend_BE'
        elif 'l' in endness:
            endness = 'Iend_LE'
            endness_unsure = True
        elif 'b' in endness:
            endness = 'Iend_BE'
            endness_unsure = True
        else:
            endness = 'Iend_LE'
            endness_unsure = True

        ident = ident.lower()
        if 'ppc64' in ident or 'powerpc64' in ident:
            if endness_unsure:
                endness = 'Iend_BE'
            return ArchPPC64(endness)
        elif 'ppc' in ident or 'powerpc' in ident:
            if endness_unsure:
                endness = 'Iend_BE'
            if bits == 64:
                return ArchPPC64(endness)
            return ArchPPC32(endness)
        elif 'mips' in ident:
            if 'mipsel' in ident:
                if bits == 64:
                    return ArchMIPS64('Iend_LE')
                return ArchMIPS32('Iend_LE')
            if endness_unsure:
                if bits == 64:
                    return ArchMIPS64('Iend_BE')
                return ArchMIPS32('Iend_BE')
            if bits == 64:
                return ArchMIPS64(endness)
            return ArchMIPS32(endness)
        elif 'arm' in ident or 'thumb' in ident:
            if endness_unsure:
                if 'l' in ident or 'le' in ident:
                    endness = 'Iend_LE'
                elif 'b' in ident or 'be' in ident:
                    endness = 'Iend_BE'
            if bits == 64:
                return ArchARM64(endness)
            return ArchARM32(endness)
        elif 'aarch' in ident:
            return ArchARM64(endness)
        elif 'amd64' in ident or ('x86' in ident and '64' in ident) or 'x64' in ident:
            return ArchX64('Iend_LE')
        elif '386' in ident or 'x86' in ident or 'metapc' in ident:
            if bits == 64:
                return ArchX64('Iend_LE')
            return ArchX86('Iend_LE')

        raise ArchError("Could not search arch!")