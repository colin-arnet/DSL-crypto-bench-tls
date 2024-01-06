#!/bin/bash
make
./main -len 4096 -num 1000 -runs 1000 -data_path /home/carnet/crypto-bench-tls/data/software
make clean