import os
import json
with open("syscal-table.txt", "r") as f:
    lines = f.readlines()
res = {}
for line in lines:
    if line.startswith('#'):
        continue
    line = line.strip().split('\t')
    if len(line) < 2:
        continue
    print(line)
    idx = int(line[0])
    callName = line[2]
    res[idx] = callName
with open("syscallIndex.json", "w") as f:
    json.dump(res, f)
