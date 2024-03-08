import os
from subprocess import PIPE, Popen

import csv
__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

def toFloat(str, precent = True):
    return round(float(str)*(100 if precent else 1), 2)

Applications = ['nginx', 'httpd', 'redis', 'sqlite', 'memcached', 'bind', 'tar']
binaryName = ['nginx', 'httpd', 'redis', 'sqlite', 'memcached', 'named', 'tar']

Overhead = ["Runtime Overhead", "Binary Expansion", "Analysis Time(s)", "Binary Size(MiB)"]

outputPath = "../outputs/tables"
resultsPath = '../outputs'
if not os.path.isdir(outputPath):
    os.mkdir(outputPath)

ana_sec = [0 for i in Applications]
with open(os.path.join(resultsPath, "DynBox", "analysis_time")) as f:
    analysis = f.readlines()

with open(os.path.join(outputPath, "Table5.csv"),"w") as csvfile: 
    writer = csv.writer(csvfile)
    writer.writerow([""] + Applications)

    payloads = []
    rateDynBox = [-1 for i in Applications]
    for idx, app in enumerate(binaryName):
        for line in analysis:
            if Applications[idx] in line:
                ana_sec[idx] = int(line.split('=')[-1][:-3]) / 1000.0
                ana_sec[idx] = toFloat(ana_sec[idx], False)
                
    runtime = [0 for i in Applications]
    size_rel = [0 for i in Applications]
    size_ori = [0 for i in Applications]
    with open("../outputs/DynBox/overhead", 'r') as f:
        lines = f.readlines()
    for line in lines:
        for idx, app in enumerate(Applications):
            if app in line:
                line = line.strip().split(" ")
                if "Runtime" in line[0]:
                    runtime[idx] = str(toFloat(line[-1]))+"%"
                elif 'Binary' in line[0]:
                    size_rel[idx] = str(toFloat(line[-1]))+"%"
                else:
                    size_ori[idx] = str(toFloat(float(line[-1])/1000000,False))

        

    writer.writerow(["Runtime Overhead"] + runtime)        
    writer.writerow(["Binary Expansion"] + size_rel)
    writer.writerow(["Analysis Time(s)"] + ana_sec)  
    writer.writerow(["Binary Size(MiB)"] + size_ori)  
