import os
import json
import argparse
import re
import sys
syscallIndexFile = os.path.join(sys.path[0], "../syscallProcess/syscallIndex.json")
with open(syscallIndexFile, "r") as f:
    syscallIndex = json.load(f)

syscallName = {}
payloads = {}
critical_syscalls = ["clone", "execve", "fork", "chmod", "mprotect", "setuid", "setgid", "accept", "bind", "listen", "sendto", "recvfrom", "socket"]
apps = ["nginx", "httpd", "redis", "sqlite", "memcached", "bind", "tar"]
results = [[] for i in apps]


def format_print(head, res, log_file=None, precent=False):
    print("{:<10}".format(head+","), end="")
    if log_file:
        log_file.write("{:<10}".format(head+","))
    for out in res:
        if type(out) is float:
            out = str(round(out * (100 if precent else 1),2))
        print("{:<10}".format(out + ("%" if precent else "")+","), end="")
        if log_file:
            log_file.write("{:<10}".format(out + ("%" if precent else ""))+",")
    if log_file:
        log_file.write("\n")
    print()


def evaluateOne(app, jsonPath, payloads):

    with open(jsonPath, 'r') as f:
        CallFile = json.load(f)
    cves = CallFile["vulnerabilities"]
    
    for key,val in syscallIndex.items():
        syscallName[val] = key


        
    repeat_count = 0
    repeat_count_after = 0
    succ = [0 for i in critical_syscalls]
    # print(len(cves))
    for cve in cves:
        requireCallVectors = cve["requiredCalls"]
        for requireCallsAll in requireCallVectors:
            requireCalls = set(requireCallsAll['requiredCalls'])
            isServer = False
            if -1 in requireCalls:
                isServer = True
                requireCalls.remove(-1)
                repeat_count_after += 1
                continue
            else:
                repeat_count += 1
                

            for id, critical in enumerate(critical_syscalls):
                criticalId = int(syscallName[critical])
                if criticalId not in requireCalls:
                    # print(criticalId, 43  in requireCalls)
                    succ[id] += 1
    rate = []
    for id, critical in enumerate(critical_syscalls):
        rate.append(succ[id] * 1.0 / repeat_count)
    
    results[apps.index(app)] = rate



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--defense', "-d", required=True, help="defense result dir")
    parser.add_argument('--target', "-t", required=False, help="evaluation target", choices=apps)

    args = parser.parse_args()
    payloads_file = os.path.join(sys.path[0], "syscallPerPayload.json")
    
    if not os.path.isdir(args.defense):
        os.mkdir(args.defense)

    with open(payloads_file, 'r') as f:
        payloads = json.load(f)
    re_syscall = re.compile("\(([\d]*)\).*")
    tot_payload=0
    log_file = os.path.join(sys.path[0], "criticalSyscall.txt")
    log_file = open(log_file, "w")
    for key, payload in payloads.items():
        tot_payload+=1
        payloadCalls = set()
        payloadCalls_s = payload['syscalls']
        for syscall in payloadCalls_s:
            index = int(re_syscall.match(syscall)[1])
            payloadCalls.add(index)
        payload['syscalls'] = payloadCalls

    if not os.path.isdir(args.defense):
        assert(False , "the provided directory is invalid")
    if args.target is None:
        allJson = os.listdir(args.defense)
        for appName in apps:
            # appName = cveJsonFile.split("-")[0]
            cveJsonFile = os.path.join(args.defense, appName+"-cve.json")
            evaluateOne(appName, cveJsonFile, payloads)
        

        usage = [0 for i in critical_syscalls]

        for index_s, payload in payloads.items():
            payloadCalls = payload['syscalls']
            for id, critical in enumerate(critical_syscalls):
                    criticalId = int(syscallName[critical])
                    if criticalId in payloadCalls:
                        usage[id] += 1
        
        rate_usage = []
        for id, critical in enumerate(critical_syscalls):
            rate_usage.append(usage[id] * 1.0 / len(payloads))
            # print(critical, rate_usage[-1])

        # print("syscalls in payload")
        print("critical syscalls")
        format_print("App", critical_syscalls, log_file)
        print("-"*135)
        log_file.write("-"*135 + "\n")
        format_print("payloads", rate_usage, log_file, True)
        print("-"*135)
        log_file.write("-"*135 + "\n")
        for idx, app in enumerate(apps):
            format_print(app, results[idx], log_file)
        print("-"*135)
        log_file.write("-"*135 + "\n")

    else:
        app = args.target
        cveJsonFile = os.path.join(args.defense, app+"-cve.json")
        evaluateOne(app, cveJsonFile, payloads)
        print("syscalls in payload")
        # print(critical_syscalls)
        format_print("App", critical_syscalls)
        print("-"*135)
        format_print(app, results[apps.index(app)])
        print("-"*135)





