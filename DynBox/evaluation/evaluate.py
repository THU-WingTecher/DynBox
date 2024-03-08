import os
import json
import argparse
import re
import openpyxl
import numpy as np
syscallIndexFile = "./syscallProcess/syscallIndex.json"
with open(syscallIndexFile, "r") as f:
    syscallIndex = json.load(f)
syscallName = {}
payloads = {}

Applications = ['nginx', 'httpd', 'redis', 'sqlite', 'memcached', 'bind', 'tar']



countAll = {
    "priviledge" : {},
    "command" : {},
    "network" : {},
    "file" : {},
    "all" : {}
}

countServer = {
    "priviledge" : {},
    "command" : {},
    "network" : {},
    "file" : {},
    "all" : {}
}

numbers = []



sumPayload = 0



def outputRes(title, Result, div, log_file):
    print(title)
    log_file.write(title+"\n")
    # print(Result)
    res = []
    res_str="Application"
    for key, CurCount in Result.items():
            res_str += (',\t' + key )

    print(res_str)
    log_file.write(res_str+"\n")
    res_str="Defense Count:"
    i=0
    for key, CurCount in Result.items():
        res_str +=  ('\t ' + str(CurCount['succ'] *1.0 / div))
        # print(numbers)
        # print(CurCount['succ'] *1.0 / div / CurCount['tot'])
        i+=1
    print(res_str)
    log_file.write(res_str+"\n")

    res_str="Defense Rate"
    for key, CurCount in Result.items():
        # print(CurCount['tot'])
        rate = CurCount['succ'] * 1.0 / CurCount['tot'] / div
        res.append(rate)
        res_str += ( ', ' + str(rate))
    print(res_str)
    log_file.write(res_str+"\n")

    print("\n\n")
    return res


    
def initDicts():
    for key, value in countAll.items():
        countAll[key] = {
            "tot" : 0,
            "succ" : 0,
            "fail" : 0
        }
        countServer[key] = {
            "tot" : 0,
            "succ" : 0,
            "fail" : 0
        }



def processDynBox(cves, targetApp, logFile):
    payloads_file = "./evaluation/syscallPerPayload.json"
    res = []
    re_syscall = re.compile("\(([\d]*)\).*")
    with open(payloads_file, 'r') as f:
        payloads = json.load(f)

    for key, payload in payloads.items():
        countAll[payload['type']]['tot'] += 1
        countAll["all"]['tot'] += 1
        countServer[payload['type']]['tot'] += 1
        countServer["all"]['tot'] += 1
        payloadCalls = set()
        payloadCalls_s = payload['syscalls']
        for syscall in payloadCalls_s:
            index = int(re_syscall.match(syscall)[1])
            payloadCalls.add(index)
        payload['syscalls'] = payloadCalls

       
    tot = 0
    fail = 0
    succ = 0
    fail_payload = set()
    succ_payload = set()

    repeat_count = 0
    repeat_count_after = 0
    callNumber = 0
    callNumberServer = 0
    for cve in cves:
        requireCallVectors = cve["requiredCalls"]
        for requireCallsAll in requireCallVectors:
            # print(requireCallsAll)
            requireCalls = set(requireCallsAll['requiredCalls'])
            isServer = False
            count = countAll
            if -1 in requireCalls:
                isServer = True
                count = countServer
                requireCalls.remove(-1)
                callNumberServer += len(requireCalls)
                repeat_count_after += 1
            else:
                repeat_count += 1
                callNumber += len(requireCalls)

            for index_s, payload in payloads.items():
                # index = int(index_s[:3])
                pType = payload["type"]
                payloadCalls = payload['syscalls']
                intersect = requireCalls.intersection(payloadCalls)
                if len(intersect) == len(payloadCalls):
                    count[pType]['fail'] += 1
                    count['all']["fail"] += 1         
                else:
                    count[pType]['succ'] += 1
                    count['all']["succ"] += 1

                    # if(pType == "fileOps") and isServer:
                    #     succ_payload.add(index_s)
                        # print("fail file ops", index)

    print()
    res += outputRes("DynBox Whole Life Cycle on " + targetApp, countAll, repeat_count, logFile)

    outputRes("DynBox Serving Phase on " + targetApp, countServer, repeat_count_after, logFile)


    res_str = f"Average Permitted Syscall Number of Whole Life Cycle on Application {targetApp}: {callNumber / repeat_count}"
    print(res_str)
    logFile.write(res_str + "\n")
    res_str = f"Average Permitted Syscall Number of Serving Phase on Application {targetApp}: {callNumberServer / repeat_count_after}"
    print(res_str, "\n")
    logFile.write(res_str + "\n")
    logFile.close()
    

    res_str = str(list(fail_payload))

    return res


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--defense', "-d", required=True, help="defense result file about blocked cve")
    # parser.add_argument("--result", '-r', required=False, help="directory save results", default="/home/zzzzzq/sda/defense/seccomp-runtime/evaluation/results/")
    parser.add_argument("--target", "-t", required=True, help="evaluation target")
    args = parser.parse_args()
   
    if not os.path.isdir(args.defense):
        os.mkdir(args.defense)
   
    for key,val in syscallIndex.items():
        syscallName[val] = key
       

    if args.target == "all":
        allData = []
        workbook = openpyxl.Workbook() 
        sheet = workbook.create_sheet(index=0)
        sheet.append(["Application", "DynBox", "DynBox", "DynBox", "DynBox", "DynBox"])
        sheet.append(["vulnerabilities",'Priviledge', "Command", "Network", "SystemOps", "Total", "Count"])
       
        for app in Applications:
            initDicts()
            log_file = open(os.path.join(args.defense, app+".out"), "w")
            with open(os.path.join(args.defense, app+"-cve.json"), 'r') as f:
                CallFile = json.load(f)
            cves = CallFile['vulnerabilities']
            res = [app]
            res += processDynBox(cves, app, log_file)
            allData.append(res[1:])
            
            sheet.append(res)
        allData = np.array(allData)
        average = np.average(allData, axis=0)
        sheet.append(["average"] + list(average))
        print(os.path.join(args.defense, "category.xlsx"))
        workbook.save(os.path.join(args.defense, "category.xlsx"))
    else:
        log_file = open(os.path.join(args.defense, args.target+".out"), "w")
        with open(os.path.join(args.defense, args.target+"-cve.json"), 'r') as f:
            CallFile = json.load(f)
        cves = CallFile['vulnerabilities']
        initDicts()
        processDynBox(cves, args.target, log_file)