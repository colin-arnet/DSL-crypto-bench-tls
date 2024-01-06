import os
import sys
import subprocess
import time

REPO_PATH = "/home/carnet/crypto-bench-tls/"
DATA_PATH = REPO_PATH + "data/"
PLOT_PATH = REPO_PATH + "plots/"
SOFTWARE_DATA_PATH = DATA_PATH + "software/"
HARDWARE_DATA_PATH = DATA_PATH + "hardware/"
SOFTWARE_SRC_PATH = REPO_PATH + "src/"
HARDWARE_SRC_PATH = REPO_PATH + "Vitis_Libraries/security/L1/benchmarks/"
HARDWARE_BENCH_PATH_LIST = [
"aes256GcmEncrypt", 
"aes256GcmDecrypt", 
"aes128GcmEncrypt_2", 
"aes128GcmDecrypt", 
"aes128Ccm8Encrypt", 
"aes128Ccm8Decrypt",
"aes128Ccm12Encrypt",
"aes128Ccm12Decrypt",
"aes128Ccm16Encrypt",
"aes128Ccm16Decrypt",
"chacha20poly1305Encrypt"
]
RUN_OPTION = 100
LEN_OPTIONS = [64, 128, 256, 512, 1024, 2048, 4096, 8192]
NUM_OPTIONS = [64, 128, 256, 512, 1024, 2048, 4096, 8192]

def print_help():
    help_message = """
    Options available with driver.py:

    pyhton3 driver.py -help
    prints this message.

    pyhton3 driver.py -clean_all
    clean up all benchmarks

    python3 driver.py -clean_software
    clean up software benchmarks

    python3 driver.py -clean_hardware
    clean up hardware benchmarks

    python3 driver.py -compile_hardware_sw
    compile and run hardware benchmarks with the software emulation

    python3 driver.py -compile_hardware_hw
    compile for alveo-250u card

    python3 driver.py -compile_hardware_hw_emu
    compile harware emulation

    python3 driver.py -compile_software
    compiles the software benchmark

    python3 driver.py -run_software_default
    compiles and runs the software benchmark with default settings
    
    python3 driver.py -run_software_extended
    compiles and runs the software benchmark with different configurations

    python3 driver.py -run_hardware_default
    run hardware benchmark with default configuration on the alveo-u250 card

    python3 driver.py -run_hardware_extended
    run hardware benchmark with different configurations on the alveo-u250 card
    """
    print(help_message)

def clean_all():
    print("cleanup software and hardware benchmark")
    clean_software()
    clean_hardware()

def clean_software():
    print("cleanup software benchmark")
    command = "make clean"
    p = subprocess.Popen(command.split(), cwd=SOFTWARE_SRC_PATH)
    p.wait()

def clean_hardware():
    print("cleanup hardware benchmark")
    command = "make cleanall"
    for bench in HARDWARE_BENCH_PATH_LIST:
        src_path = HARDWARE_SRC_PATH + bench
        p = subprocess.Popen(command.split(), cwd = src_path)
        p.wait()

def compile_hardware_sw():
    print("compile and run software emulation")
    command = "make run TARGET=sw_emu PLATFORM=/opt/xilinx/platforms/xilinx_u250_gen3x16_xdma_4_1_202210_1/xilinx_u250_gen3x16_xdma_4_1_202210_1.xpfm"
    for bench in HARDWARE_BENCH_PATH_LIST:
        src_path = HARDWARE_SRC_PATH + bench
        p = subprocess.Popen(command.split(), cwd = src_path)
        p.wait()

def compile_hardware_hw():
    print("compile hardware version")
    command = "make run TARGET=hw PLATFORM=/opt/xilinx/platforms/xilinx_u250_gen3x16_xdma_4_1_202210_1/xilinx_u250_gen3x16_xdma_4_1_202210_1.xpfm"
    for bench in HARDWARE_BENCH_PATH_LIST:
        src_path = HARDWARE_SRC_PATH + bench
        p = subprocess.Popen(command.split(), cwd = src_path)
        p.wait()

def compile_hardware_hw_emu():
    print("compile and run hardware emulation")
    command = "make run TARGET=hw_emu PLATFORM=/opt/xilinx/platforms/xilinx_u250_gen3x16_xdma_4_1_202210_1/xilinx_u250_gen3x16_xdma_4_1_202210_1.xpfm"
    for bench in HARDWARE_BENCH_PATH_LIST:
        src_path = HARDWARE_SRC_PATH + bench
        p = subprocess.Popen(command.split(), cwd = src_path)
        p.wait()

def compile_software():
    print("compile software benchmark")
    command = "make"
    p = subprocess.Popen(command.split(), cwd=SOFTWARE_SRC_PATH)
    p.wait()

def run_software_default():
    print("compile and run software benchmark in default config")
    compile_software()
    command = "./main -len 1024 -num 1000 -runs 10 -data_path " + DATA_PATH + "software/"
    p = subprocess.Popen(command.split(), cwd=SOFTWARE_SRC_PATH)
    p.wait()

def generate_options():
    options = []
    for length in LEN_OPTIONS:
        for num in NUM_OPTIONS:
            option = (length, num)
            options.append(option)
    return options
    
def run_software_extended():
    print("compile and run software benchmark with different configurations")
    compile_software()
    options = generate_options()
    for (length, num) in options:
        command = "./main -len " + str(length)+ " -num " + str(num) + " -runs " + str(RUN_OPTION) + " -data_path " + DATA_PATH + "software/"
        p = subprocess.Popen(command.split(), cwd=SOFTWARE_SRC_PATH)
        p.wait()

def run_hardware_default():
    print("run hardware benchmark with default configuration on the alveo-u250 card")
    for bench in HARDWARE_BENCH_PATH_LIST:
        build_dir = "/build_dir.hw.xilinx_u250_gen3x16_xdma_4_1_202210_1/"
        host = "./" + bench + "Benchmark.exe"
        xclbin = "./" + bench + "Kernel.xclbin"
        path = HARDWARE_SRC_PATH + bench + build_dir
        command = "xbutil reset --device 0000:06:00.1 --force"
        p = subprocess.Popen(command.split(), cwd=path)
        p.wait()
        command = host + " -xclbin " + xclbin + " -len 1024 -num 1000 -runs 10 -data_path " + HARDWARE_DATA_PATH
        p = subprocess.Popen(command.split(), cwd=path)
        p.wait()

        


def run_hardware_extended():
    print("run hardware benchmark with different configurations on the alveo-250u card")
    # reset FPGA
    for bench in HARDWARE_BENCH_PATH_LIST:
        build_dir = "/build_dir.hw.xilinx_u250_gen3x16_xdma_4_1_202210_1/"
        host = "./" + bench + "Benchmark.exe"
        xclbin = "./" + bench + "Kernel.xclbin"
        path = HARDWARE_SRC_PATH + bench + build_dir
        command = "xbutil reset --device 0000:06:00.1 --force"
        p = subprocess.Popen(command.split(), cwd=path)
        p.wait()
        options = generate_options()
        for (length, num) in options:
            command = host + " -xclbin " + xclbin + " -len " + str(length) + " -num " + str(num) + " -runs " +  str(RUN_OPTION) + " -data_path " + HARDWARE_DATA_PATH
            p = subprocess.Popen(command.split(), cwd=path)
            p.wait()
            command = "xbutil reset --device 0000:06:00.1 --force"
            p = subprocess.Popen(command.split(), cwd=path)
            p.wait()
    

def main():
    argv = sys.argv
    if len(argv) > 2:
        print("ONLY ONE OPTION AT A TIME")
        print_help()
        return
    if "-help" in argv:
        print_help()
        return
    if "-clean_all" in argv:
        clean_all()
        return
    if "-clean_software" in argv:
        clean_software()
        return
    if "-clean_hardware" in argv:
        clean_hardware()
        return
    if "-compile_software" in argv:
        compile_software()
        return
    if "-compile_hardware_sw" in argv:
        compile_hardware_sw()
        return
    if "-compile_hardware_hw_emu" in argv:
        compile_hardware_hw_emu()
        return
    if "-compile_hardware_hw" in argv:
        compile_hardware_hw()
        return
    if "-run_software_default" in argv:
        run_software_default()
        return
    if "-run_software_extended" in argv:
        run_software_extended()
        return
    if "-run_hardware_default" in argv:
        run_hardware_default()
        return
    if "-run_hardware_extended" in argv:
        run_hardware_extended()
        return
    print("OPTION INVALID")
    print_help()

if __name__ == "__main__":
    main()