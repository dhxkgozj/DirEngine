# -*- coding: utf-8 -*-


import capstone
import pyvex

from Functions.Function import Function
from Functions.Branch import Branch
from Functions.Function_block import Function_block
from Functions.Branch_block import Branch_block
class FunctionsManager:
    _header = None
    _options = {}
    functions = []
    def __init__(self,header,options):
        self._header = header
        self._options = options


    def analyze(self):
        self.functions = []
        CodeFlowManager(self).analyze()



class CodeFlowManager:
    _manager = None
    _header = None
    fqueue = []
    fqueue_sucess = []
    def __init__(self,manager):
        self._manager = manager
        self._header = self._manager._header
        self.fqueue = []
        pyvex.set_iropt_level(1)

    def analyze(self):

        self._initlize_function()

        while True:
            if self.fqueue == []:
                break

            fb = self.fqueue.pop(0)
            print "Function : ",hex(fb.addr)
            self.handle_function(fb)

        print "Function count is " ,len(self.fqueue_sucess)

    def fqueue_append(self,fb):
        if not fb.addr in self.fqueue_sucess:
            self.fqueue.append(fb)
            self.fqueue_sucess.append(fb.addr)


    def _initlize_function(self):
        fb = Function_block(self._header._entry + self._header.base_addr,entry_function=True)
        self.fqueue_append(fb)


    def _initlize_branch(self,fb):
        addr = fb.addr
        fb.bqueue_append(Branch_block(fb,0,addr))


    def handle_function(self,fb):

        self._initlize_branch(fb)

        count = 1
        while True:
            if fb.bqueue == []:
                break

            bb = fb.bqueue.pop(0)
            irsb , insn = self.disasmble(bb)
            bb.set_irsb(irsb)
            bb.set_insn(insn)

            self.handle_branch(bb)
            count += 1


    def handle_branch(self,bb):
        irsb = bb.irsb
        self.irsb_constants(irsb.constants)
        try:
            if irsb.jumpkind == "Ijk_Boring":
                if irsb.direct_next is True:
                    if int(str(irsb.next),16) == bb.addr:
                        bb.fb.bqueue_append(Branch_block(bb.fb,(bb.count + 1 ),(bb.addr + int(str(irsb.size),16))))
                        return

                    if irsb.stmts_used == 1:
                        self.fqueue_append(Function_block(int(str(irsb.next),16)))
                        return

                    bb.fb.bqueue_append(Branch_block(bb.fb,(bb.count + 1 ),int(str(irsb.next),16)))
                    if isinstance(irsb.statements[len(irsb.statements)-1],pyvex.IRStmt.Exit):
                        insert_addr = irsb.statements[len(irsb.statements)-1].dst
                        if type(insert_addr) is pyvex.IRExpr.Const:  # pylint: disable=unidiomatic-typecheck
                            target_addr = insert_addr.con.value
                        elif type(insert_addr) in (pyvex.IRConst.U32, pyvex.IRConst.U64):  # pylint: disable=unidiomatic-typecheck
                            target_addr = insert_addr.value
                        elif type(insert_addr) in (int, long):  # pylint: disable=unidiomatic-typecheck
                            target_addr = insert_addr
                        else:
                            target_addr = None
                            import pdb
                            pdb.set_trace()
                        bb.fb.bqueue_append(Branch_block(bb.fb,(bb.count + 2),target_addr))


            elif irsb.jumpkind == "Ijk_Call":
                if irsb.direct_next is True:
                    self.fqueue_append(Function_block(int(str(irsb.next),16)))
                bb.fb.bqueue_append(Branch_block(bb.fb,(bb.count + 1 ),bb.addr + irsb.size))

            elif irsb.jumpkind == "Ijk_Ret":
                pass

            elif irsb.jumpkind == "Ijk_SigTRAP":
                bb.fb.bqueue_append(Branch_block(bb.fb,(bb.count + 1 ),int(str(irsb.next),16)))

            elif irsb.jumpkind == "Ijk_NoDecode":
                pass
            else:
                import pdb
                pdb.set_trace()
        except:
            import pdb
            pdb.set_trace()


    def irsb_constants(self,constants):
        for constant in constants:
            int(str(constant),16)


    def disasmble(self,bb):
        insn = []
        buff = self._header.read_bytes(self._header.read_addr(bb.addr-self._header.base_addr))
        addr = bb.addr
        arch = self._header.arch
        irsb = pyvex.IRSB(buff,addr,arch,num_bytes=400,bytes_offset=0,traceflags=0)
        bytestring = buff[:irsb.size]
        cs = arch.capstone
        for cs_insn in cs.disasm(bytestring,addr):
            insn.append(cs_insn)
            #print hex(cs_insn.address).replace("L",''), cs_insn.mnemonic, cs_insn.op_str

        return irsb, insn


