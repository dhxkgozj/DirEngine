


class Function_block:
    addr = None
    name = None
    entry_function = False
    const_jump = False
    bqueue = {}
    bqueue_sucess = {}
    signature = {}
    expr = {}
    edge = {}
    operation = {}
    assemble_count = {}
    def __init__(self,addr,const_jump=False,entry_function=False):
        self.addr = addr
        self.name = "sub_" + str(hex(addr))
        self.entry_function = entry_function
        self.xref_fb_to = []
        self.xref_fb_from = []
        self.xref_const_to = []
        self.const_jump = const_jump
        self.signature = {
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
        self.expr = {
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
        self.edge = {
            'node' : 0,
            'in' : 0,
            'out' : 0
        }
        self.operation = {}
        self.assemble_count = {}
        self.bqueue = {}
        self.bqueue_sucess = {}

    def bqueue_append(self,bb):
        if not str(bb.addr) in self.bqueue_sucess.keys():
            if not str(bb.addr) in self.bqueue.keys():
                self.bqueue[str(bb.addr)] = bb
                self.edge['node'] += 1
        self.edge['in'] += 1

    def set_xref_src_fb(self,desc_fb):
        self.xref_fb_from.append(desc_fb.addr)
        self.edge['out'] += 1

    def set_xref_desc_fb(self,src_fb):
        self.xref_fb_to.append(src_fb.addr)

    def set_xref_const_desc_fb(self,src_bb):
        self.xref_const_to.append(src_bb.addr)