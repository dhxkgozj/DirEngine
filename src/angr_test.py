import angr


pro = angr.Project("taint.exe")

cfg = pro.analyses.CFGAccurate()
