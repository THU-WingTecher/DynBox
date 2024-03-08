import os

import csv

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

def toFloat(str, precent = True):
    return round(float(str)*(100 if precent else 1), 2)

Applications = ['nginx', 'httpd', 'redis', 'sqlite', 'memcached', 'bind', 'tar']
outputPath = "../outputs/tables"
resultsPath = '../outputs'
if not os.path.isdir(outputPath):
    os.mkdir(outputPath)
with open(os.path.join(outputPath, "Table2.csv"),"w") as csvfile: 
    writer = csv.writer(csvfile)
    writer.writerow(["Applications","Whole Lifecycle Defense Result", "", "", "", "", "", "Serving Phase Defense Result"])
    writer.writerow(["","Chesnut", "Chesnut", "Temp", "Temp", "DynBox", "DynBox","Chesnut", "Chesnut", "Temp", "Temp", "DynBox", "DynBox"])
    writer.writerow(["","Rate", "Count", "Rate", "Count", "Rate", "Count", "Rate", "Count", "Rate", "Count", "Rate", "Count"])
    totChesWhole = totChesWholeRate = tottempWholeRate = tottempWhole = totdynWholeRate = totdynWhole = tottempServer = tottempServerRate = totdynServingRate = totdynServing = 0
    for app in Applications:
        DynBox_resFile = os.path.join(resultsPath, "DynBox", app+".out")
        with open(DynBox_resFile, 'r') as f:
            dynlines = f.readlines()
        dynWhole = toFloat(dynlines[-2].split(": ")[-1], False)
        dynServing = toFloat(dynlines[-1].split(": ")[-1], False)
        dynWholeRate = toFloat(dynlines[3].split(", ")[-1])
        dynServingRate = toFloat(dynlines[7].split(", ")[-1])
        totdynWhole += dynWhole
        totdynServing += dynServing
        totdynWholeRate += dynWholeRate
        totdynServingRate += dynServingRate
        
        Temp_resFile = os.path.join(resultsPath, "temp", app, "defenseRate.txt")
        with open(Temp_resFile, 'r') as f:
            templines = f.readlines()
        tempWholeRate = toFloat(templines[0].split(", ")[1], False)
        tempServerRate = toFloat(templines[0].split(", ")[0], False)
        Temp_resFile = os.path.join(resultsPath, "temp", app, "syscallreduction")
        with open(Temp_resFile, 'r') as f:
            templines = f.readlines()
        tempWhole = toFloat(templines[1].split(";")[-2], False)
        tempServing = toFloat(templines[1].split(";")[-1], False)
        tottempWhole += tempWhole
        tottempServer += tempServing
        tottempWholeRate += tempWholeRate
        tottempServerRate += tempServerRate


        Chesnut_resFile = os.path.join(resultsPath, "chesnut", app+".chesnut")
        with open(Chesnut_resFile, 'r') as f:
            cheslines = f.readlines()
        chesWhole = toFloat(cheslines[-1].split(": ")[-1].strip(), False)
        # print(cheslines[-1].split(": ")[-1].strip())
        chesWholeRate = toFloat(cheslines[3].split(", ")[-1])
        totChesWhole += chesWhole
        totChesWholeRate += chesWholeRate

        writer.writerow([app, chesWholeRate, chesWhole, tempWholeRate, tempWhole, dynWholeRate, dynWhole, chesWholeRate, chesWhole, tempServerRate, tempServing, dynServingRate, dynServing])
    lenApp = len(Applications)
    writer.writerow(["Average", 
        toFloat(totChesWholeRate / lenApp, False), 
        toFloat(totChesWhole / lenApp, False), 
        toFloat(tottempWholeRate / lenApp, False), 
        toFloat(tottempWhole / lenApp, False), 
        toFloat(totdynWholeRate / lenApp, False), 
        toFloat(totdynWhole / lenApp, False), 
        toFloat(totChesWholeRate / lenApp, False), 
        toFloat(totChesWhole / lenApp, False), 
        toFloat(tottempServerRate / lenApp, False), 
        toFloat(tottempServer / lenApp, False), 
        toFloat(totdynServingRate / lenApp, False), 
        toFloat(totdynServing / lenApp, False)])

