import json
import os
import sys
import argparse
import subprocess

targets = ["nginx", "httpd", "redis", "sqlite", "memcached", "bind", "tar"]
SYSCALL_INFO_FILE = os.path.join(sys.path[0], "../syscallProcess/syscallIndex.json")
LLVM_PATH = os.path.join(sys.path[0], "../llvm/llvm-12/")
PASS_PATH = os.path.join(sys.path[0], "../llvm/PartialOrderAnalysis.so")
6


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', "-t", required=True, help="target application of building DynBox", choices=targets)
    args = parser.parse_args()
    FilePath = sys.path[0]
    ConfigPath = os.path.join(FilePath, "config.json")
    with open(ConfigPath, "r") as f:
        Config = json.load(f)
    
    Config = Config[args.target]
    SOLIB_SYSCALL = os.path.join(FilePath, "..", Config["DynLibMapping"])
    print(SOLIB_SYSCALL)
    CALLSITE_INFO =  os.path.join(FilePath, "..", Config["IndirectCalls"])
    vulnerabilities = os.path.join(FilePath, "..", Config["vulnerabilities"])
    evaluationOutput = os.path.join(FilePath, "..", Config["evaluationOutput"])
    inputBc = os.path.join(FilePath, "..", Config["bcfile"])
    outputBc = os.path.join(FilePath, f"../targets/bcFiles/{args.target}.seccomp.bc")

    optPath = os.path.join(LLVM_PATH, "bin/opt")

    os.environ["SOLIB_SYSCALL"] = SOLIB_SYSCALL
    os.environ["SYSCALL_INFO_FILE"] = SYSCALL_INFO_FILE
    os.environ["CALLSITE_INFO"] = CALLSITE_INFO

    cmdLine = [optPath, "-enable-new-pm=0" ,"-load", PASS_PATH , "-partial-order-analysis",  "--enable-sandbox", "--vulnerabilities", vulnerabilities, "--evaluation-output", evaluationOutput, inputBc, "-o", outputBc]
    print(" ".join(cmdLine))
    res = subprocess.call(cmdLine, stdout=sys.stdout, stderr=sys.stdout)





    

    