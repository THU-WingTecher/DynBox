import sys
Applications = ['nginx', 'httpd', 'redis', 'sqlite', 'memcached', 'bind', 'tar']

fout = open("outputs/DynBox/overhead", "w")

with open("evaluation/overhead", 'r') as f:
    lines = f.readlines()
    runtime_ori = lines[0].strip().split(', ')
    runtime_sec = lines[1].strip().split(', ')

    size_ori = lines[2].strip().split(', ')
    size_sec = lines[3].strip().split(', ')
    for i in range(len(Applications)):
        cur_run = abs(float(runtime_ori[i]) - float(runtime_sec[i])) / float(runtime_ori[i])
        fout.write("Runtime overhead on " + Applications[i] + " " + str(cur_run)+"\n" )
    for i in range(len(Applications)):
        cur_size = (float(size_sec[i]) - float(size_ori[i])) / float(size_ori[i])
        fout.write("Binary overhead on " + Applications[i] + " " + str(cur_size)+"\n" )
    for i in range(len(Applications)):
        fout.write("Size of " + Applications[i] + " " + str(size_ori[i])+"\n" )
