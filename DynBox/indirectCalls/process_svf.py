import json
import os
import subprocess
from sys import argv
import psutil
import re
curPath = os.getcwd()
# tail call void %16(i8* %10) #28, !dbg !15584  at ../src/aio/aio.c:187:3 ### UNRESOLVED
callRe = re.compile('CallSite:    .* { ln: (\d*)  cl: (\d*)  fl: (.*) }.*Location:.*')
calleesRe = re.compile('	(.*)\n')
def processStats(stasFile):
    curCallSite = None
    final_res = {}
    curRes = []
    with open(stasFile, 'r') as f:

        lines = f.readlines()
    for line in lines:
        # line = line.strip()
        if line.strip() == "" or "NodeID:" in line:
            continue
        if (res := callRe.match(line)):
            fileName = res.group(3)
            lineNum = res.group(1)
            col = res.group(2)
            curCallSite = fileName+":"+lineNum+":"+col
            curRes = []
            final_res[curCallSite] = curRes
            print("get new call site", curCallSite)
        elif "!!!has no targets!!!" in line:
            print(curCallSite, "has not target")
            continue
        elif (res := calleesRe.match(line)):
            callee = res.group(1)
            # print(callees)
            curRes.append(callee)
        else:
            print("fail to handle line:", line[:-1])
    # print(final_res)
    jsonFile = os.path.join(curPath, 'indirectCalls.json')
    with open(jsonFile, 'w') as f:
        json.dump(final_res, f, sort_keys=True)


if __name__ == "__main__":
    # processStats('./stats.txt')
    # exit(1)
    file = argv[1]
    
    os.environ["SVF_DIR"] = "./SVF"
    os.environ["LLVM_DIR"] = "./SVF/llvm-12.0.0.obj"
    os.environ["Z3_DIR"] = "./SVF/z3.obj"
    os.environ["PATH"] =":".join([ os.environ["PATH"], os.environ["LLVM_DIR"] +"/bin", os.environ["SVF_DIR"] + "/Release-build-13/bin" ])
    statsFile = os.path.join(curPath, 'stats.txt') 
    cmdLine = ["wpa", "-print-fp", "-ander", "-dump-callgraph", file]
    print(cmdLine)
    curRes = []
    with open(statsFile , 'w') as f:
        res = subprocess.call(cmdLine, stdout=f, stderr=f)
    
    processStats(statsFile)



            
            
