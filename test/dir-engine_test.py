import DirEngine

d = DirEngine.Project("/bin/sh")

d.Analysis()

function = d.fm.CF.fqueue_sucess[str(d.fm.CF.fqueue_sucess.keys().pop(0))]

branch = function.bqueue_sucess[str(function.bqueue_sucess.keys().pop(0))]



branch.irsb.pp()

branch.insn_pp()