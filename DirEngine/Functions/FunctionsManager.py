# -*- coding: utf-8 -*-


import capstone
import pyvex

from .Function import Function
from .Branch import Branch
from .Function_block import Function_block
from .Branch_block import Branch_block
from multiprocessing import Process,Queue


class FunctionsManager:
    _header = None
    _options = {}
    functions = []
    ###############################
    functions = [] # 함수 리스트
    mne_count = {} # 전체 어셈블리 빈도수

    def __init__(self,header,options):
        self._header = header
        self._options = options
        self._sig_bit = True
        self.branch_count = 0 # branch 개수


    def analyze(self,bit=True):
        self.functions = []
        self.CF = CodeFlowManager(self)
        self.CF.analyze()

        if bit is True:
            pass
            #self._Analysis_Functions(self.CF.fqueue_sucess)


    def _Analysis_Functions(self,f):
        f_list = f.values() 
        result = Queue()
        f1 = []
        f2 = []
        f3 = []
        #f4 = []
        #f5 = []
        aver_size = len(f_list) / 4
        plus = len(f_list) % 4


        for i in xrange(0,aver_size):
            f1.append(f_list.pop())
        for i in xrange(0,aver_size):
            f2.append(f_list.pop())
        for i in xrange(0,aver_size):
            f3.append(f_list.pop())
        #for i in xrange(0,aver_size):
        #    f4.append(f_list.pop())      
        #for i in xrange(0,aver_size):
        #    f5.append(f_list.pop())                   
        for i in xrange(0,plus):
            f1.append(f_list.pop())

        p1 = Process(target = self._Process, args= (f1,result))
        p2 = Process(target = self._Process, args= (f2,result))
        p3 = Process(target = self._Process, args= (f3,result))
        #p4 = Process(target = self._Process, args= (f4,result))
        #p5 = Process(target = self._Process, args= (f5,result))
        p1.start()
        p2.start()
        p3.start()
        #p4.start()
        #p5.start()

        p1.join()
        p2.join()
        p3.join()
        #p4.join()
        #p5.join()

        result.put('STOP')
        sum = 0
        while True:
            tmp = result.get()
            if tmp == 'STOP' : break
            else: self.functions.extend(tmp)

    def _Process(self,f_list,result):
        functions = []
        for _f in f_list:
            function = _f
            print hex(function.addr)
            fnc = self._Get_Function(function)
            functions.append(fnc) 
        result.put(functions)

    '''
    def _Analysis_Functions(self,f):
        Process(targetas = self._Get_Function, args= (function,result))
        for _f in f.keys():
            function = f[_f]
            print hex(function.addr)
            self._Get_Function(function)
            self.functions.append(function) 
            


    def _Analysis_Functions(self,f):
        functions = []
        processing = []
        result = Queue()


        for _f in f.keys():
            function = f[_f]
            print hex(_f.addr) , "START"
            processing.append(Process(targets = self._Get_Function, args= (function,result)))
            processing[len(processing)-1].start()
        
        result.put('OK')
        for process in processing:
            process.join()

        while True:
            tmp = result.get()
            if tmp == 'OK': break

            else:
                print hex(tmp.addr) 
                functions.append(tmp) 
            

        return functions
    '''

    def _Get_Function(self,f):
        fnc = {}
        fnc['blocks'] = []
        fnc['xref_to'] = f.xref_fb_to
        fnc['xref_from'] = f.xref_fb_from
        fnc['addr'] = f.addr
        fnc['symbol'] = str(f.name)
        fnc['signature'] = {
            'Ist_NoOp' : 0,
            'Ist_IMark' : 0,
            'Ist_AbiHint' : 0,
            'Ist_Put' : 0,
            'Ist_PutI' : 0,
            'Ist_WrTmp' : 0,
            'Ist_Store' : 0,
            'Ist_CAS' : 0,
            'Ist_LLSC' : 0,
            'Ist_MBE' : 0,
            'Ist_Dirty' : 0,
            'Ist_Exit' : 0,
            'Ist_LoadG' : 0,
            'Ist_StoreG' : 0
        }
        fnc['expr'] = {
            'Iex_Binder' : 0,
            'Iex_Get' : 0,
            'Iex_RdTmp' : 0,
            'Iex_Qop' : 0,
            'Iex_Triop' : 0,
            'Iex_Binop' : 0,
            'Iex_Unop' : 0,
            'Iex_Load' : 0,
            'Iex_Const' : 0,
            'Iex_CCall' : 0,
            'Iex_ITE' : 0
        }
        fnc['edge'] = {
            'node' : 0,
            'in' : 0,
            'out' : 0
        }
        fnc['operation'] = {}
        fnc['total_signature'] = {}
        fnc['assemble_count'] = {}

        branchs = f.bqueue_sucess
        if(self._sig_bit == True):
            fnc['edge']['in'] = 0
            fnc['edge']['out'] = len(fnc['xref_from'])
        for branch in branchs:
            fnc['blocks'].append(self._Get_Branch(f,fnc,branch))
        if(self._sig_bit == True):
            fnc['edge']['node'] = len(fnc['blocks'])
        fnc['total_signature'].update(fnc['signature'])
        fnc['total_signature'].update(fnc['expr'])
        fnc['total_signature'].update(fnc['edge'])
        return fnc

    def _Get_Vex_Signatures(self,vex,f,b):
        for stat in vex['statements']:
            if(stat['tag'] in f['signature'].keys()):
                f['signature'][stat['tag']] += 1
            else:
                f['signature'][stat['tag']] = 1

            if(stat['tag'] == "Ist_WrTmp"):
                self._Get_Expr_Signatures(stat,f,b)


    def _Get_Edge_Signatures(self,vex,f,b):
        if('in' in f['edge'].keys()):
            f['edge']['in'] += len(b['b_from'])
        else:
            f['edge']['in'] = 0
            f['edge']['in'] += len(b['b_from'])


    def _Get_Expr_Signatures(self,stat,f,b):
        tag = stat['data']['tag']
        if(tag in f['expr'].keys()):    
            f['expr'][tag] += 1

        if('op' in stat['data'].keys()):
            self._Get_Op_Signatures(stat,f,b)

    def _Get_Op_Signatures(self,stat,f,b):
        op = stat['data']['op']
        if(op in f['operation'].keys()):    
            f['operation'][op] += 1
        else:
            f['operation'][op] = 1


    def _Get_Branch(self,f,fnc,b):
        bnc = {}
        bnc['vex'] = self._Get_Vex(b.irsb,fnc)
        bnc['capstone'] = self._Get_Capstone(b.insn,fnc)
        bnc['b_to'] = []
        bnc['b_from'] = []
        bnc['addr'] = b.addr
        bnc['count'] = b.count
        if(self._sig_bit == True):
            self._Get_Vex_Signatures(bnc['vex'],fnc,bnc)
        for _to in b.xref_bb_to:
            bnc['b_from'].append(_to.addr)
        for _from in b.xref_bb_from:
            bnc['b_to'].append(_from.addr)

        if(self._sig_bit == True):
            self._Get_Edge_Signatures(bnc['vex'],fnc,bnc)
        self.branch_count += 1
        return bnc


    def _Get_Capstone(self,c,fnc):
        capstone = {}
        capstone['insns'] = []
        for i in c:
            capstone['insns'].append(self._Get_Insn(i,fnc))
        return capstone

    def _Get_Insn(self,i,fnc):
        insn = {}
        insn['operands'] = []
        insn['mnemonic'] = i.mnemonic
        if(self._sig_bit == True):
            self._Get_mne_count(insn['mnemonic'])
            self._Get_fun_mne_count(insn['mnemonic'],fnc)
        insn['bytes'] = str(i.bytes).decode('latin-1')
        insn['address'] = i.address
        insn['op_str'] = i.op_str
        count = 0
        for operand in i.operands:
            insn['operands'].append(self._Get_Operand(operand,count))
            count += 1
        return insn


    def _Get_Operand(self,o,count):
        operand = {}
        operand['count'] = count
        operand['reg'] = o.reg
        operand['imm'] = o.imm
        operand['type'] = o.type
        operand['size '] = o.size
        operand['mem'] = {
            'disp' : o.mem.disp,
            'index' : o.mem.index,
            'base' : o.mem.base,
            'segment' : o.mem.segment,
            'scale' : o.mem.scale
        }
        return operand

    def _Get_Vex(self,v,fnc):
        vex = {}
        vex['statements'] = []
        vex['offsIP'] = v.offsIP
        vex['jumpkind'] = v.jumpkind
        vex['stmts_used'] = v.stmts_used
        vex['direct_next'] = v.direct_next
        vex['instructions'] = v.instructions
        vex['size'] = v.size
        vex['typenv'] = v.tyenv.types
        vex['operations'] = v.operations

        for statement in v.statements:
            vex['statements'].append(self._Get_Statement(statement))
        return vex

    old_addr = 0
    stat_count = 0
    def _Get_Statement(self,s): # 태그마다 나눠서 처리 해야함 (미구현)
        stat = {}
        stat['tag'] = s.tag
        stat['pp'] = str(s)
        if isinstance(s,pyvex.stmt.IMark):
            self.old_addr = s.addr
            self.stat_count = 0
        stat['count'] = self.stat_count
        stat['addr'] = self.old_addr

        if isinstance(s,pyvex.stmt.WrTmp):
            stat['data'] = {}
            stat['data']['tag'] = s.data.tag
            if('op' in s.data.__dict__.keys()):
                stat['data']['op'] = s.data.op

        self.stat_count += 1
        return stat

    # 어셈명령 빈도
    def _Get_mne_count(self,mne):
        if self.mne_count.has_key(mne):
            self.mne_count[mne] += 1
        else:
            self.mne_count[mne] = 1

    # 어셈명령 빈도
    def _Get_fun_mne_count(self,mne,fnc):
        if fnc['assemble_count'].has_key(mne):
            fnc['assemble_count'][mne] += 1
        else:
            fnc['assemble_count'][mne] = 1



class CodeFlowManager:
    _manager = None
    _header = None
    fqueue = {}
    fqueue_sucess = {}
    new_fb_list = {}
    main_section = ""
    def __init__(self,manager):
        self._manager = manager
        self._header = self._manager._header
        self.fqueue = {}
        self.fqueue_sucess = {}
        self.new_fb_list = {}
        self.new_bb_list = []
        pyvex.set_iropt_level(1)

    def analyze(self):

        self._initlize_function()

        while True:
            if self.fqueue == {}:
                break

            fb = self.fqueue[self.fqueue.keys().pop(0)]
            if(str(fb.addr) in self.fqueue_sucess.keys()):
                continue

            self.FuncAnaStart_Handler(fb)
            self.handle_function(fb)
            self.FuncAnaEnd_Handler(fb)
            print "Function : " , hex(fb.addr)

        print "Function count is " ,len(self.fqueue_sucess)

    def fqueue_append(self,fb):
        if(str(fb.addr) not in self.fqueue_sucess.keys()):
            if(str(fb.addr) not in self.fqueue.keys()):
                self.fqueue[str(fb.addr)] = fb


    def _initlize_function(self):
        fb = self.new_fb(Function_block(self._header._entry + self._header.base_addr,entry_function=True))
        self.main_section = self._manager._header.is_section(fb.addr).Name
        self.fqueue_append(fb)


    def _initlize_branch(self,fb):
        addr = fb.addr
        fb.bqueue_append(Branch_block(fb,0,addr))


    def handle_function(self,fb):

        self._initlize_branch(fb)

        count = 1
        while True:
            if fb.bqueue == {}:
                break

            bb = fb.bqueue[fb.bqueue.keys().pop(0)]
            irsb , insn = self.disasmble(bb)
            bb.set_irsb(irsb)
            bb.set_insn(insn)

            self.handle_branch(bb)
            count += 1
            self.BranchAnaEnd_Handler(bb)

    def handle_branch(self,bb):
        irsb = bb.irsb
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

        self.irsb_constants(bb)



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


    def FuncAnaStart_Handler(self,fb):
        if(self._manager._header.filetype == 'pe'):
            ret = self._manager._header.iat_symbol(fb.addr)
            if ret != False:
                fb.name = ret




    def FuncAnaEnd_Handler(self,fb):
        if(str(fb.addr) not in self.fqueue_sucess.keys()):
            self.fqueue_sucess[str(fb.addr)] = fb
            del self.fqueue[str(fb.addr)]


    def BranchAnaStart_Handler(self,bb):
        pass

    def BranchAnaEnd_Handler(self,bb):
        if not str(bb.addr) in bb.fb.bqueue_sucess.keys():
            bb.fb.bqueue_sucess[str(bb.addr)] = bb
            del bb.fb.bqueue[str(bb.addr)]

    def irsb_constants(self,bb):
        irsb = bb.irsb
        constants = irsb.constants
        jump_targets = list(irsb.constant_jump_targets)
        for constant in constants:
            constant = int(str(constant),16)

            if irsb.direct_next is True:
                if constant == int(str(irsb.next),16): #next 인경우
                    continue

            if constant in jump_targets: #jump target 인경우
                continue

            if constant == (bb.addr + irsb.size): #next block
                continue

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
                if constant == target_addr:
                    continue

            try:
                if self.main_section == self._manager._header.is_section(constant).Name: # 간접 Address Functio Block
                    new_fb = self.new_fb(Function_block(constant,const_jump=True))
                    self.xref_const(bb,new_fb)
                    self.fqueue_append(new_fb)
            except Exception,e:
                pass


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


    def xref_const(self,src_bb,desc_fb): # B->Function Block Xref
        src_bb.set_xref_const_src_fb(desc_fb)
        desc_fb.set_xref_const_desc_fb(src_bb)


    def new_fb(self,fb):
        if(str(fb.addr) not in self.new_fb_list.keys()):
            self.new_fb_list[str(fb.addr)] = fb

        return self.new_fb_list[str(fb.addr)]


    def new_bb(self,bb):
        self.new_bb_list.append(bb)
        return self.new_bb_list[len(self.new_bb_list)-1]        


