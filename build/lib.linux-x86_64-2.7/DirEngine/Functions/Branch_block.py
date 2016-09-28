


class Branch_block:
    fb = None
    count = None
    function_addr = None
    addr = None
    insn = []
    irsb = None
    def __init__(self,fb,count,addr):
        self.fb = fb
        self.count = count
        self.function_addr = fb.addr
        self.addr = addr
        self.xref_bb_to = []
        self.xref_bb_from = []
        self.xref_const_from = []


    def set_irsb(self,irsb):
        self.irsb = irsb
        self._irsb_analysis()

    def set_insn(self,insn):
        self.insn = insn
        self._insn_analysis()

    def set_xref_src_bb(self,desc_bb):
        self.xref_bb_from.append(desc_bb)

    def set_xref_desc_bb(self,src_bb):
        self.xref_bb_to.append(src_bb)


    def set_xref_const_src_fb(self,desc_fb):
        self.xref_const_from.append(desc_fb)


    def insn_pp(self):
        for i in self.insn:
            print i.mnemonic + " " + i.op_str



    def _irsb_analysis(self):
        for stat in self.irsb.statements:
            if(stat.tag in self.fb.signature.keys()):
                self.fb.signature[str(stat.tag)] += 1
            else:
                self.fb.signature[str(stat.tag)] = 1

            if(str(stat.tag) == "Ist_WrTmp"):
                tag = stat.data.tag
                if (str(tag) in self.fb.expr.keys()):
                    self.fb.expr[tag] += 1

                if ('op' in stat.data.__dict__.keys()):
                    op = stat.data.op
                    if(str(op) in self.fb.operation.keys()):
                        self.fb.operation[str(op)] += 1
                    else:
                        self.fb.operation[str(op)] = 1 


    def _insn_analysis(self):
        for i in self.insn:
            if self.fb.assemble_count.has_key(str(i.mnemonic)):
                self.fb.assemble_count[str(i.mnemonic)] += 1
            else:
                self.fb.assemble_count[str(i.mnemonic)] = 1


