# -*- coding: utf-8 -*-


import capstone
import pyvex

from .Function import Function
from .Branch import Branch
from .Function_block import Function_block
from .Branch_block import Branch_block
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
    new_fb_list = []
    def __init__(self,manager):
        self._manager = manager
        self._header = self._manager._header
        self.fqueue = []
        self.new_fb_list = []
        self.new_bb_list = []
        pyvex.set_iropt_level(1)

    def analyze(self):

        self._initlize_function()

        while True:
            if self.fqueue == []:
                break

            fb = self.fqueue.pop(0)
            print "Function : ",hex(fb.addr)
            self.handle_function(fb)
            import pdb
            pdb.set_trace()
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
                self.Boring_Handler(bb,irsb)

            elif irsb.jumpkind == "Ijk_Call":
                self.Call_Handler(bb,irsb)

            elif irsb.jumpkind == "Ijk_Ret":
                self.Ret_Handler(bb,irsb)

            elif irsb.jumpkind == "Ijk_SigTRAP":
                self.SigTrap_Handler(bb,irsb)

            elif irsb.jumpkind == "Ijk_NoDecode":
                self.Nodecode_Handler(bb,irsb)
            else:
                print "$error$ [handle_branch] : irsb jumpkind Code Not found"
                import pdb
                pdb.set_trace()
        except Exception ,e :
            print e
            import pdb
            pdb.set_trace()


    def Boring_Handler(self,bb,irsb):
        if irsb.direct_next is True:
            if int(str(irsb.next),16) == bb.addr: # 자기 자신을 가르킨 경우
                new_bb = self.new_bb(Branch_block(bb.fb,(bb.count + 1 ),(bb.addr + int(str(irsb.size),16))))
                self.xref_bb(bb,new_bb)
                bb.fb.bqueue_append(new_bb) #다음 명령어부터 타 블록으로 간주
                return

            if irsb.stmts_used == 1: #JMP 명령어만 존재하는 경우
                new_fb = self.new_fb(Function_block(int(str(irsb.next),16)))
                self.xref_fb(bb.fb,new_fb)
                self.fqueue_append(new_fb)
                return

            new_bb = self.new_bb(Branch_block(bb.fb,(bb.count + 1 ),int(str(irsb.next),16)))
            self.xref_bb(bb,new_bb)
            bb.fb.bqueue_append(new_bb) # 일반적인 JUMP일 경우


            if isinstance(irsb.statements[len(irsb.statements)-1],pyvex.IRStmt.Exit): # 조건 점프일경우
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
                new_bb = self.new_bb(Branch_block(bb.fb,(bb.count + 2),target_addr))
                self.xref_bb(bb,new_bb)
                bb.fb.bqueue_append(new_bb)



    def Call_Handler(self,bb,irsb):
        if irsb.direct_next is True: # 직접 점프일 경우
            new_fb = self.new_fb(Function_block(int(str(irsb.next),16)))
            self.xref_fb(bb.fb,new_fb)
            self.fqueue_append(new_fb)
        new_bb = self.new_bb(Branch_block(bb.fb,(bb.count + 1 ),bb.addr + irsb.size))
        self.xref_bb(bb,new_bb)
        bb.fb.bqueue_append(new_bb)
        # 간접 점프, IAT, 레지스터등에 고려가 안되있음.

    def Ret_Handler(self,bb,irsb):
        pass 

    def SigTrap_Handler(self,bb,irsb):
        new_bb = self.new_bb(Branch_block(bb.fb,(bb.count + 1 ),int(str(irsb.next),16)))
        self.xref_bb(bb,new_bb)
        bb.fb.bqueue_append(new_bb) 


    def Nodecode_Handler(self,bb,irsb):
        pass

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


    def xref_bb(self,src_bb,desc_bb): # Branch Block Xref
        src_bb.set_xref_src_bb(desc_bb)
        desc_bb.set_xref_desc_bb(src_bb)

    def xref_fb(self,src_fb,desc_fb): # Function Block Xref
        src_fb.set_xref_src_fb(desc_fb)
        desc_fb.set_xref_desc_fb(src_fb)


    def new_fb(self,fb):
        self.new_fb_list.append(fb)
        return self.new_fb_list[len(self.new_fb_list)-1]


    def new_bb(self,bb):
        self.new_bb_list.append(bb)
        return self.new_bb_list[len(self.new_bb_list)-1]        
