import os

import csv
__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

def toFloat(str, precent = True):
    return round(float(str)*(100 if precent else 1), 2)

Applications = ['nginx', 'httpd', 'redis', 'sqlite', 'memcached', 'bind', 'tar']

CriticalSyscalls = ["clone", "execve", "fork", "chmod", "mprotect", "setuid", "setgid", "accept", "bind", "listen", "sendto", "recvfrom", "socket"]
typeSyscall = ["Cmd", "Cmd", "Cmd", "Priviledge", "Priviledge", "Priviledge", "Priviledge", "Priviledge", "Network", "Network", "Network", "Network", "Network", "Network"]
outputPath = "../outputs/tables"
resultsPath = '../outputs'
if not os.path.isdir(outputPath):
    os.mkdir(outputPath)
with open(os.path.join(outputPath, "Table4.csv"),"w") as csvfile: 
    writer = csv.writer(csvfile)
    writer.writerow(["Applications","Syscall", "Payloads", "nginx", "nginx", "httpd", "httpd", "redis", "redis",  "sqlite", "sqlite", "memcached", "memcached", "bind", "bind", "tar", "tar"])
    writer.writerow(["","", "", "nginx", "nginx", "httpd", "httpd", "redis", "redis",  "sqlite", "sqlite", "memcached", "memcached", "bind", "bind", "tar", "tar"])
    writer.writerow(["", "", "", "Temp", "DynBox", "Temp", "DynBox", "Temp", "DynBox", "Temp", "DynBox", "Temp", "DynBox", "Temp", "DynBox", "Temp", "DynBox",])
    DynBoxSyscallFile = open(os.path.join(__location__, "../", "evaluation", "criticalSyscall.txt"))
    DynLines = DynBoxSyscallFile.readlines()
    payloads = []
    rateDynBox = [-1 for i in Applications]

    for i in range(len(DynLines)):
        DynLines[i] = DynLines[i].replace(" ", "").strip().split(",")
        line = DynLines[i]
        # print(line)
        if 'payloads' == line[0]:
            payloads = line
            
        if line[0] in Applications:
            pos = Applications.index(line[0])
            rateDynBox[pos] = line

    rateTemp = [-1 for i in Applications]
    for rowId , syscall in enumerate(CriticalSyscalls):
        res = [typeSyscall[rowId], CriticalSyscalls[rowId], payloads[rowId+1]]
        for idx, app in enumerate(Applications):
            Temp_resFile = os.path.join(resultsPath, "temp", app, "sensitive")
            Temp_resFilelines = open(Temp_resFile, "r").readlines()
            for line in Temp_resFilelines:
                line = line.strip().split(";")
                if line[0] != syscall:
                    continue
                if "overall" in line[2]:
                    rateTemp[idx] = 1-float(line[-1])
        for appIdx in range(len(Applications)):
            res.append(round(rateTemp[appIdx], 2))
            # print(rateDynBox[appIdx])
            res.append(round(float(rateDynBox[appIdx][rowId+1]),2))
        writer.writerow(res)        

