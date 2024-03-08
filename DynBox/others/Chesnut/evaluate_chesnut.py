import os
import json
import argparse
import re
import openpyxl
import numpy as np
__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

syscallIndexFile = __location__+"/../../syscallProcess/syscallIndex.json"
with open(syscallIndexFile, "r") as f:
    syscallIndex = json.load(f)
syscallName = {}
payloads = {}

Applications = ['nginx', 'httpd', 'redis', 'sqlite', 'memcached', 'bind', 'tar']



countChu = {
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
    for key, value in countChu.items():
        countChu[key] = {
            "tot" : 0,
            "succ" : 0,
            "fail" : 0
        }


def processTemp(requireCalls, targetApp, log_file):
    requireCalls = set(requireCalls)
    payloads_file = __location__+"/../Temporal-Specialization/security-evaluation/syscallPerPayload.json"
    with open(payloads_file, 'r') as f:
        payloads = json.load(f)
    for key, payload in payloads.items():
        countChu["all"]["tot"] += 1
        countChu[payload['type']]["tot"] += 1

        payloadCalls = set()
        payloadCalls_s = payload['syscalls']
        re_syscall = re.compile("\(([\d]*)\).*")

        for syscall in payloadCalls_s:
            index = int(re_syscall.match(syscall)[1])
            payloadCalls.add(index)
        payload['syscalls'] = payloadCalls



    failed = []
    repeat_count = 1
    count = countChu
    for index_s, payload in payloads.items():
        
        pType = payload['type']
        payloadCalls = payload['syscalls']
        intersect = requireCalls.intersection(payloadCalls)
        if len(intersect) == len(payloadCalls):
            # if(getIndex(index) == "openPort") and isServer:
            #     print("fail", index)
            count[pType]['fail'] += 1
            count['all']["fail"] += 1
            failed.append(index_s)
            
        else:
            count[pType]['succ'] += 1
            count['all']["succ"] += 1
        

    # print(countChu)
    outputRes("Results of Chesnut on " + targetApp, countChu, repeat_count, log_file)

    res_str = f"Permitted Syscall Number of Chesnut on {targetApp}: {len(requireCalls)}"
    print(res_str, "\n")
    log_file.write(res_str+"\n")
    log_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--syscall', "-s", required=True, help="Permitted syscalls of Chesnut")
    parser.add_argument("--result", '-r', required=True, help="directory save results", default="../../outputs")
    parser.add_argument("--target", "-t", required=True, help="evaluation target")
    args = parser.parse_args()
   

   
    for key,val in syscallIndex.items():
        syscallName[val] = key
       
    resultDir = os.path.join(args.result, "chesnut")
    if not os.path.isdir(resultDir):
        os.mkdir(resultDir)

    if args.target == "all":
        allData = []
       
       
        for app in Applications:
            initDicts()
            log_file = open(os.path.join(resultDir, app+".chesnut"), "w")
            callFile = os.path.join(__location__, "permitted_syscalls", app+"-chu.json")
            with open(callFile) as f:
                calls = json.load(f)['MainCalls']
            processTemp(calls, app, log_file)
            
            
    else:
        log_file = open(os.path.join(resultDir, args.target+".out"), "w")
        callFile = os.path.join(__location__, "permitted_syscalls", args.target+"-chu.json")
        with open(callFile) as f:
            calls = json.load(f)['MainCalls']
        # print(calls)
        initDicts()
        processTemp(calls, args.target, log_file)