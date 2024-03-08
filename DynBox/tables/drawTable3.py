import os

import csv

def toFloat(str, precent = True):
    return round(float(str)*(100 if precent else 1), 2)

Applications = ['httpd-bit', 'httpd-dru', 'nginx', 'redis', 'memcached', 'tar-czvf', 'tar-xvzf', 'tar-test']
Applications_name = ['httpd', 'httpd', 'nginx', 'redis', "memcached", 'tar', 'tar', 'tar']
Configuration = ["Wordpress", "Mediawiki", "Zend Server", "default", "Ubuntu Default", "-czvf", "-xzvf", "-test-label"]
outputPath = "../outputs/tables"
resultsPath = '../outputs'
if not os.path.isdir(outputPath):
    os.mkdir(outputPath)
with open(os.path.join(outputPath, "Table3.csv"),"w") as csvfile: 
    writer = csv.writer(csvfile)
    writer.writerow(["", "Applications"] +Applications_name + ["Average"])
    writer.writerow(["","Configuration"] + Configuration)
    
    totdyn = totdynRate = totC2C = totC2CRate = 0
    dynList = []
    dynRateList = []
    C2CList = []
    C2CRateList = []

    for idx, app in enumerate(Applications):

        DynBox_resFile = os.path.join(resultsPath, "DynBox", Applications_name[idx]+".out")
        with open(DynBox_resFile, 'r') as f:
            dynlines = f.readlines()
        dyn = toFloat(dynlines[-1].split(": ")[-1], False)
        dynRate = toFloat(dynlines[7].split(", ")[-1])
        totdyn += dyn
        totdynRate += dynRate
        dynList.append(dyn)
        dynRateList.append(dynRate)
       

        C2C_resFile = os.path.join(resultsPath, "C2C", app+".C2C")
        with open(C2C_resFile, 'r') as f:
            C2Clines = f.readlines()
        C2CWhole = toFloat(C2Clines[-1].split(": ")[-1].strip(), False)
        # print(C2Clines[-1].split(": ")[-1].strip())
        C2CWholeRate = toFloat(C2Clines[3].split(", ")[-1])
        totC2C += C2CWhole
        totC2CRate += C2CWholeRate
        C2CList.append(str(C2CWhole)+"%")
        C2CRateList.append(str(C2CWholeRate)+"%")

    writer.writerow(["Permitted Syscall","C2C"] + C2CList + [toFloat(totC2C/len(Applications), False)])
    writer.writerow(["Permitted Syscall","DynBox"] + dynList + [(toFloat(totdyn/len(Applications), False))])

    writer.writerow(["Defense Rate","C2C"] + C2CRateList + [toFloat(totC2CRate/len(Applications), False)])
    writer.writerow(["Defense Rate","DynBox"] + dynRateList + [str(toFloat(totdynRate/len(Applications), False))+"%"])


