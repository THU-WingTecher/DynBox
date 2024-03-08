import json
from locale import normalize
import cle
import re
import os
import argparse
import angr
import time
import pickle
import sys
from regex import E
from sqlalchemy import null
import syscalls
ignore_set = set(["libc.so.6"])
mustInclude = ["fstat64", "stat64", 
                "lstat64", "stat", 
                "fstat", "lstat", "fstatat"]

current_ms = lambda: int(round(time.time() * 1000))
callsite_cache = {}
function_cache = {}
extern_func_required = {}

solved_librays = set()
loadded_library = {}
cfg_names = {}
cfg_folder = ""
# existing_library = {}
Emulate = True

def init_global():
    # global callsite_cache
    callsite_cache.clear()
    function_cache.clear()
    extern_func_required.clear()

def load_cfg_names(cfg_path):
    cfgs = os.listdir(cfg_path)
    global cfg_folder
    cfg_folder = cfg_path
    for cfg in cfgs:
        if cfg.endswith("pkl"):
            cfg_names[cfg[:-4]] = os.path.join(cfg_path, cfg)


def start_time():
    global current
    current = current_ms()
    
def stop_time(msg):
    global current
    delta = current_ms() - current
    print("[%dms] %s" % (delta, msg))
    current = current_ms()

def build_function_cache(cfg):
    global function_cache

    print("Building function cache...")
    
    for f in cfg.kb.functions:
        start = 2**63
        end = 0
        fnc = cfg.kb.functions[f]
        if fnc in extern_func_required:
            continue
        # print(fnc.name, fnc.project)
        project = fnc.project
        for block in fnc.blocks:
            if block.size == 0: #skip blocks with size 0
                continue
            start = min(block.addr, start)
            end = max(block.addr + block.size, end)

        function_cache[fnc] = (start, end)

def load_export_funcs(obj, cfg):
    export_func = {}
    for symbol in obj.symbols:
        if symbol.is_export:
            if symbol.rebased_addr in cfg.kb.functions:
                export_func[symbol.name] = cfg.kb.functions[symbol.rebased_addr]
    
    return export_func

def get_start_funcs(obj):
    export_func = set()
    for symbol in obj.symbols:
        if symbol.is_export:
            export_func.add(symbol.rebased_addr)
    
    return list(export_func)
            
            
def load_extern_functions(extern_objs):
    global extern_func_required
    extern_func_required.clear()
    print("loading externing functions")

    def add_extern_functions(extern_obj):
        for symbol in extern_obj.symbols:
            name = symbol.name
            extern_func_required[name] = symbol.rebased_addr
    if type(extern_objs) is list:
        for extern_obj in extern_objs:
            add_extern_functions(extern_obj)
                # assert(symbol is not None, "should have symbol "+name)
    else:
        add_extern_functions(extern_objs)
            # extern_func_required.append(())
    return extern_func_required

def function_calling_syscalls(cfg, sys_addrs):
    syslist = {} 
    # map all syscall addresses to functions
    for sys_addr in sys_addrs:
        fnc = find_function(cfg, sys_addr)
        if not fnc:
            print("??? syscall unknown position")
            continue
        if fnc not in syslist:
            syslist[fnc] = set()
        syslist[fnc].add(sys_addr)

    return syslist

def find_function(cfg, vaddr):
    if len(function_cache) == 0:
        build_function_cache(cfg)

    for f in function_cache:
        if vaddr >= function_cache[f][0] and vaddr < function_cache[f][1]:
            return f

    return None

def get_call_sites(fnc):
    global callsite_cache

    if fnc not in callsite_cache:
        callsite_cache[fnc] = fnc.get_call_sites()
    return callsite_cache[fnc]

    

def get_call_targets(cfg):
    callgraph = {}

    # extract all call targets
    for f in cfg.kb.functions:
        fnc = cfg.kb.functions[f]

        call_sites = get_call_sites(fnc)
        calls = []
        for c in call_sites:
            callers = fnc.get_call_target(c)
            if callers is list:
                for caller in callers:
                     calls.append((c, caller))
                print("get indirect call")
            else:
                calls.append((c, callers))

        for call in calls:
            gf = find_function(cfg, call[1])
            if gf:
                if gf.name == "sub_a8f60":
                    continue
                if fnc not in callgraph:
                    callgraph[fnc] = set()
                callgraph[fnc].add(gf)
            else:
                print("!!!error, unknown external function")
                # extern_func_required.add(call[1])
                continue
    return callgraph


def get_syscalls(cfg, fnc, callees, syslist, found = set(), traversed = set()):
    if fnc in traversed:
        return found

    # if fnc in 

    traversed.add(fnc)
    if fnc in syslist:
        found.update(syslist[fnc])
    if fnc in callees:
        for c in callees[fnc]:
            if c.name in extern_func_required:
                found.add(c)
            else:
                found.update(get_syscalls(cfg, c, callees, syslist, found, traversed))
    return found

def syscalls_per_function(cfg, callgraph, syslist, export_func):
    syscaller = {}
    global extern_func_required
    for func_name, func in export_func.items():
        if func.name in extern_func_required: 
            continue
        calls = get_syscalls(cfg, func, callgraph, syslist, set(), set())
        # if len(calls) > 0:
        syscaller[func_name] = calls
    # for func in callgraph:
    #     if func.name in extern_func_required: 
    #         continue
    #     calls = get_syscalls(cfg, func, callgraph, syslist, set(), set())
    #     # if len(calls) > 0:
    #     syscaller[func.name] = calls

    # for func in syslist:
    #     if func in extern_func_required: 
    #         continue
    #     calls = get_syscalls(cfg, func, callgraph, syslist, set(), set())
    #     # if len(calls) > 0:
    #     syscaller[func.name] = calls

    return syscaller


def load_all_solved_libs(solved_libs_path):
    file_list = os.listdir(solved_libs_path)
    for lib_file in file_list:
        if not lib_file.endswith(".json"):
            continue
        lib_file_path = os.path.join(solved_libs_path, lib_file)
        with open(lib_file_path, 'r') as f:
            libs = json.load(f)
        loadded_library[lib_file[:-5]] = libs
        solved_librays.add(lib_file[:-5])
    with open(sys.path[0]+"/libcsyscalls/libc.so.6.json", "r") as f:
        libs = json.load(f)
        loadded_library["lib.so.6"] = libs
        solved_librays.add("lib.so.6")
def loadCfg(binary_path, binary_name):
    start_time()
    init_global()


    insn, base_addr = syscalls.init(binary_path)
    stop_time("Syscall Init")
    addrs = syscalls.find_syscall_locations(insn)
    stop_time("Syscall locations")
    sys_addrs = [x for x in addrs]


    try:
        if binary_name in cfg_names:
            with open(cfg_names[binary_name], 'rb') as f:
                cfg = pickle.load(f)
            program = cfg.project
        else:
            program = angr.Project(binary_path, load_options={"auto_load_libs": False, 'main_opts': {'base_addr': 0}})
            # start_funcs = get_start_funcs(program.loader.all_objects[0])
            cfg = program.analyses.CFGFast(show_progressbar=True, fail_fast=True, 
            # cfg = program.analyses.CFGEmulated(show_progressbar=True, fail_fast=True, starts = start_funcs,
                                        resolve_indirect_jumps=True, normalize=True)            
        if cfg_folder != "":
                dump_name = os.path.join(cfg_folder, binary_name+".pkl") 
                with open(dump_name, 'wb') as f:
                    pickle.dump(cfg, f, -1)
        # if Emulate:
        #     start_funcs = get_start_funcs(program.loader.all_objects[0], cfg)
        #     cfg = program.analyses.CFGEmulated(show_progressbar=True, fail_fast=True, 
        #                                 resolve_indirect_jumps=True, normalize=True, starts = start_funcs)
        
    except:
        print("angr cannot get cfg from ", binary_path)
        exit(1)
    stop_time("Getting CFG") 
    global extern_func_required

    load_extern_functions(program.loader.extern_object)

    export_func = load_export_funcs(program.loader.all_objects[0], cfg)

    syslist = function_calling_syscalls(cfg, sys_addrs)  # return syscall in function, ignoring calls
    callGraph = get_call_targets(cfg)

    syscaller = syscalls_per_function(cfg, callGraph, syslist, export_func)
    return insn, addrs, syscaller


def processLib(binary_path, output_path):
    print("processing lib", binary_path)
    binary_name = binary_path.split("/")[-1]
    insn, addrs, syscaller = loadCfg(binary_path, binary_name)

    insn_to_syscall = {}
    used_syscalls = {}
    for fnc in syscaller:
        insn_list = set()
        for sysc in syscaller[fnc]:
            if type(sysc) is not int and sysc.name in extern_func_required:
                for lib_name,apis in loadded_library.items():
                    if sysc.name in apis:
                        insn_list.update(apis[sysc.name])
                        break
            elif sysc in addrs:
                if addrs[sysc] not in insn_to_syscall:
                    insn_to_syscall[addrs[sysc]] = syscalls.find_syscall_nr(insn, addrs[sysc])
                insn_list.add(insn_to_syscall[addrs[sysc]])
       

        used_syscalls[fnc] = sorted(list(set(insn_list))).copy()
    
    all_syscalls = set()
    
    for f in used_syscalls:
        all_syscalls.update(set(used_syscalls[f]))
    used_syscalls[":all"] = sorted(list(all_syscalls))

    with open(output_path, "w") as out:
        json.dump(used_syscalls, out, sort_keys=True)
    
    loadded_library[binary_name] = used_syscalls
    
    return used_syscalls

def processExe(binary_path, output_path, required):
    processLib(binary_path, output_path[:-5] + "-all.json")
    binary_name = binary_path.split("/")[-1]
    start_time()
    init_global()
    try:
        program = angr.Project(binary_path, load_options={"auto_load_libs": False})        
    except:
        print("angr cannot load binary ", binary_path)
        exit(1)
    stop_time("loading binary") 
    global extern_func_required
    load_extern_functions(program.loader.extern_object)
    if args.required != "":
        staticsFuncs = []
        with open(args.required , "r") as f:
            lines = f.readlines()
            for line in lines:
                extern_func_required[line.strip()] = null
    for line in mustInclude:
       extern_func_required[line.strip()] = null 

    used_syscalls = {}
    for func in extern_func_required:
        cur_useCalls = set()
        for lib_name, apis in loadded_library.items():
            if func in apis:
                cur_useCalls.update(set(apis[func]))
        used_syscalls[func] = list(cur_useCalls)
        used_syscalls[func].sort()

        if func not in used_syscalls:
            print("---fail to get syscalls of", func)
        

    if "syscall" in used_syscalls:
        used_syscalls["syscall"].append(-4)
    with open(output_path, "w") as out:
        json.dump(used_syscalls, out, sort_keys=True)
    
    loadded_library[binary_name] = used_syscalls
    
    return used_syscalls

def processAll(binary_path, output_path, required):
    binary_name = binary_path.split("/")[-1]
    if binary_name in solved_librays or binary_name in ignore_set:
        return
    solved_librays.add(binary_name)
    needed = os.popen("ldd "+binary_path)
    neededso = re.findall(r'[>](.*?)[(]', needed.read())
    all_so = []
    for so in neededso:
        so = so.strip()
        if len(so) > 0 and so not in ignore_set:
            all_so.append(so)
    
    if not os.path.isdir(output_path):
        os.makedirs(output_path)
    
    for so in all_so:
        # so_name = so.split("/")[-1].split(".")[0]
        # output_res_name = os.path.join(output_path, so_name)    
        processAll(so, output_path, required)
    output_file = os.path.join(output_path, binary_name+".json")
    if ".so" in binary_name:
        processLib(binary_path, output_file)
    else:
        processExe(binary_path, output_file, required)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", "-b", required=True, type=str, help="the path of target binary")
    parser.add_argument("--output", "-o", required=True, type=str, help="the output file path")
    parser.add_argument("--solved_libs", "-s", required=False, type=str, help="the path that saved the all solved libs", default="")
    parser.add_argument("--cfg_path", "-c", required=False, type=str, help="the path of all cfg files", default="")
    parser.add_argument("--all", "-a", action="store_true", help="process all used dso or only current dso")
    parser.add_argument("--required", "-r", type=str, required=False, default="", help="the api that required to analysis")

    args = parser.parse_args()
    if args.cfg_path != "":
        load_cfg_names(args.cfg_path)

    

    if args.solved_libs != "":
        load_all_solved_libs(args.solved_libs)

  

    if args.all:
        processAll(args.binary, args.output, args.required)
    
    else:
        if ".so" in args.binary:
            processLib(args.binary, args.output)
        else:
            processExe(args.binary, args.output)

