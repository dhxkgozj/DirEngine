import angr


pro = angr.Project("taint.exe")

cfg = pro.analyses.CFG_fast()
