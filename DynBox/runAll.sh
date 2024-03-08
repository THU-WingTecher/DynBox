#!/bin/bash


cd others/Chesnut
python3.8 evaluate_chesnut.py -s ./permitted_syscalls -t all -r ../../outputs/
cd ../

cd Temporal-Specialization
./runTemp.sh
cd ../

cd c2c
python3.8 evaluate_c2c.py -s ./permittedSyscall -r ../../outputs -t all
cd ../../


python3.8 evaluation/evaluate.py -d outputs/DynBox -t all

python3.8 evaluation/evaluate_syscalls.py -d outputs/DynBox

python3.8 evaluation/processOverhead.py

cd tables
python3.8 drawTable2.py
python3.8 drawTable3.py
python3.8 drawTable4.py
python3.8 drawTable5.py