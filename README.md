
  

# Benchmarking TLS Cipher Suites on FPGA

This is the git repository for the semester thesis. Within the scope of the Distributed Systems Lab.

## Abstract

TLS is the most widely used protocol to secure web traffic. By encrypting and authenticating the data it provides confidentiality and integrity. From a set of different crytographic operations used in TLS, the cipher suites emerged to be the most used operations of the protocol, since they encrypt/decrypt the entire application data. Since the cipher suites are heavily used, they are a attractive target to offload on a FPGA device. The Vitis security library provides HLS implementations that can be loaded onto an FPGA. In this thesis, we evaluate the performance of these functions and compare the performance to the well established OpenSSL implementations. For the AES-GCM mode the hardware functions are on one level with the

software implementations. On the other side for the AES-CCM mode, the hardware benchmark cannot keep up with the OpenSSL implementations. Nonetheless, running the cryptographic operations on a FPGA device, frees up CPU capacity for other tasks.

## How to use driver
On the top level there is a driver.py file. Which is responsible in building and running all the benchmarks. The driver has the following options:
Options available with driver.py:

`pyhton3 driver.py -help`

prints helper message.

`pyhton3 driver.py -clean_all`

clean up all benchmarks

`python3 driver.py -clean_software`

clean up software benchmarks

`python3 driver.py -clean_hardware`

clean up hardware benchmarks

`python3 driver.py -compile_hardware_sw`

compile and run hardware benchmarks with the software emulation

`python3 driver.py -compile_hardware_hw`

compile for alveo-250u card

`python3 driver.py -compile_hardware_hw_emu`

compile harware emulation

`python3 driver.py -compile_software`

compiles the software benchmark

`python3 driver.py -run_software_default`

compiles and runs the software benchmark with default settings

`python3 driver.py -run_software_extended`

compiles and runs the software benchmark with different configurations

`python3 driver.py -run_hardware_default`

run hardware benchmark with default configuration on the alveo-u250 card

`python3 driver.py -run_hardware_extended`

run hardware benchmark with different configurations on the alveo-u250 card

## How to use benchmarks
### Software benchmark
The software benchmark source code is in the `./src/` directory. With the `make` command the program is built.
The benchmark can be run with:

`./main -len <msg_size in bytes> -num <number of messages> -runs <number of benchmark runs> -data_path <path to the directory where the data must be stored>`

The benchmark is run with the specified configuration and stores its results as a `.csv` file in the data_path.
### Hardware Benchmark
The hardware benchmark source code are in the `./Vitis_Libraries/security/L1/benchmarks/<BENCHMARK_NAME>/` directory. After building the program can be run with:

`<benchmark>.exe -xclbin <benchmark_kernel>.xclbin -len <msg_size in bytes> -num <number of messages> -runs <number of benchmark runs> -data_path <path to the directory where the data must be stored>`

## Data and Plots
The measured data is stored in the `./plotter/data/` directory. It is the data used for the thesis report.
The entire plot collection can be found in `/plotter/plots/`
The `plotter.py` is the script that generated all the plots. Depending on your system it might be necessary to establish a virtual environment to properly run the script.
## Author
Colin Arnet
## Supervisors
Professor Gustavo Alonso
Zhenhao He
