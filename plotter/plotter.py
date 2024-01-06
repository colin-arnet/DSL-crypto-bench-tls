import os
import sys
import subprocess
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import statsmodels.api as sm
import pylab

benchmarks = [
    "AES_256_GCM_encrypt",
    "AES_256_GCM_decrypt",
    # "AES_128_GCM_encrypt",
    "AES_128_GCM_decrypt",
    "AES_128_CCM_8_encrypt",
    "AES_128_CCM_8_decrypt",
    "AES_128_CCM_12_encrypt",
    "AES_128_CCM_12_decrypt",
    "AES_128_CCM_16_encrypt",
    "AES_128_CCM_16_decrypt"
]
msg_sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192]
msg_nums = [64, 128, 256, 512, 1024, 2048, 4096, 8192]

def parse_filename(filename):
    filename = filename.split(".")[0]
    tokens = filename.split("_")
    msg_size = tokens.pop()
    msg_num = tokens.pop()
    name = "_".join(tokens)
    return msg_size, msg_num, name, filename

def create_directories():
    files = os.listdir("./data/software")
    plot_path = "./plots/"
    for file in files:
        _, _, name, _ = parse_filename(file)
        path = plot_path + name + "/"
        if not os.path.exists(path):
            os.mkdir(path)
        path_histograms = path + "histograms/"
        if not os.path.exists(path_histograms):
            os.mkdir(path_histograms)
        path_histograms = path + "throughput/"
        if not os.path.exists(path_histograms):
            os.mkdir(path_histograms)
        path_histograms = path + "message_rate/"
        if not os.path.exists(path_histograms):
            os.mkdir(path_histograms)

def generate_histograms():
    print("Generate Histograms")
    files = os.listdir("./data/software")
    for file in files:
        msg_size, msg_num, name, filename = parse_filename(file)
        df = pd.read_csv("./data/software/" + file)
        time = df[' time in microseconds'].to_numpy()
        bins = 40
        hist, bin_edges = np.histogram(time, bins=bins)
        plt.figure()
        plt.stairs(hist, bin_edges)
        plt.xlabel("time in microseconds")
        plt.ylabel("number of runs")
        title = "Benchmark: " + name + "\nmessage size: " + msg_size + "; number of messages: " + msg_num 
        plt.title(title)
        plt.savefig("./plots/" + name + "/histograms/software_" + filename + ".png")
        print(title)
        plt.close()
    files = os.listdir("./data/hardware")
    for file in files:
        msg_size, msg_num, name, filename = parse_filename(file)
        if "kernel" in name:
            name = name.split("_kernel")[0]
            df = pd.read_csv("./data/hardware/" + file)
            time = df[' time in microseconds'].to_numpy()
            bins = 40
            hist, bin_edges = np.histogram(time, bins=bins)
            plt.figure()
            plt.stairs(hist, bin_edges)
            plt.xlabel("time in microseconds")
            plt.ylabel("number of runs")
            title = "Benchmark: " + name + "\nmessage size: " + msg_size + "; number of messages: " + msg_num 
            plt.title(title)
            plt.savefig("./plots/" + name + "/histograms/hardware_" + filename + ".png")
            print(title)
            plt.close()

def organize_data(bench):
    print("organize data into one dictionary")
    files = os.listdir("./data/software")
    result_software = {}
    times_software = {}
    for msg_num in msg_nums:
        sizes = {}
        for msg_size in msg_sizes:
            entry = {}
            entry['time'] = 0
            entry['throughput'] = 0
            entry['message_rate'] = 0
            sizes[str(msg_size)] = entry
        result_software[str(msg_num)] = sizes
    for file in files:
        if bench in file:
            msg_size, msg_num, name, filename = parse_filename(file)
            df = pd.read_csv("./data/software/" + file)
            times = df[' time in microseconds'].to_numpy()
            throughputs = df[' throughput (GB/s)'].to_numpy()
            message_rates = np.full(times.size, msg_num, dtype=int)
            message_rates = message_rates / (times / 1000000)
            time_mean = times.mean()
            times_software[filename] = times
            throughput_mean = throughputs.mean() * 1000
            message_rate_mean = message_rates.mean()
            result_software[str(msg_num)][str(msg_size)]['time'] = time_mean
            result_software[str(msg_num)][str(msg_size)]['throughput'] = throughput_mean
            result_software[str(msg_num)][str(msg_size)]['message_rate'] = int(message_rate_mean)
    files = os.listdir("./data/hardware")
    result_hardware = {}
    times_hardware = {}
    for msg_num in msg_nums:
        sizes = {}
        for msg_size in msg_sizes:
            entry = {}
            entry['time'] = 0
            entry['throughput'] = 0
            entry['message_rate'] = 0
            sizes[str(msg_size)] = entry
        result_hardware[str(msg_num)] = sizes
    for file in files:
        if bench + "_kernel" in file:
            msg_size, msg_num, name, filename = parse_filename(file)
            df = pd.read_csv("./data/hardware/" + file)
            times = df[' time in microseconds'].to_numpy()
            throughputs = df[' throughput (GB/s)'].to_numpy()
            message_rates = np.full(times.size, msg_num, dtype=int)
            message_rates = message_rates / (times / 1000000)
            time_mean = times.mean()
            times_hardware[filename] = times
            throughput_mean = throughputs.mean() * 1000
            message_rate_mean = message_rates.mean()
            result_hardware[str(msg_num)][str(msg_size)]['time'] = time_mean
            result_hardware[str(msg_num)][str(msg_size)]['throughput'] = throughput_mean
            result_hardware[str(msg_num)][str(msg_size)]['message_rate'] = int(message_rate_mean)
    return result_software, result_hardware, times_software, times_hardware

def generate_plots(bench, data_software, data_hardware):
    print(bench)
    for msg_num in msg_nums:
        subdata_software = data_software[str(msg_num)]
        subdata_hardware = data_hardware[str(msg_num)]
        # throughput plots
        plt.figure()
        throughput = []
        for msg_size, values in subdata_software.items():
            throughput.append(values['throughput'])
        software_throughput = throughput
        plt.plot(msg_sizes, throughput, label='software', marker='o')
        throughput = []
        for msg_size, values in subdata_hardware.items():
            throughput.append(values['throughput'])
        hardware_throughput = throughput
        plt.plot(msg_sizes, throughput, label='hardware', marker='o')
        plt.xlabel("message size in bytes")
        plt.xscale("log")
        plt.ylabel("throughput in MB/s")
        plt.legend()
        title = bench + " throughput;\n" + str(msg_num) + " messages, with different message sizes"
        plt.title(title)
        plt.savefig("./plots/" + bench + "/throughput/" + bench + "_" + str(msg_num) + "_fixed_num_throughput.png")
        plt.close()

        factor = []
        for i in range(len(software_throughput)):
            factor.append(software_throughput[i] / hardware_throughput[i])
        plt.plot(msg_sizes, factor, label='factor', marker='o')
        plt.xlabel("message size in bytes")
        plt.xscale("log")
        plt.ylabel("factor between software and hardware")
        plt.legend()
        title = bench + " throughput;\n" + str(msg_num) + " messages; performance difference factor"
        plt.title(title)
        plt.savefig("./plots/" + bench + "/throughput/" + bench + "_" + str(msg_num) + "_fixed_num_throughput_factor.png")
        plt.close()

        # message rate plots
        plt.figure()
        message_rate = []
        for msg_size, values in subdata_software.items():
            message_rate.append(values['message_rate'])
        software_message_rate = message_rate
        plt.plot(msg_sizes, message_rate, label='software', marker='o')
        message_rate = []
        for msg_size, values in subdata_hardware.items():
            message_rate.append(values['message_rate'])
        hardware_message_rate = message_rate
        plt.plot(msg_sizes, message_rate, label='hardware', marker='o')
        plt.xlabel("message size in bytes")
        plt.xscale("log")
        plt.ylabel("messages per second")
        plt.legend()
        title = bench + " message_rate;\n" + str(msg_num) + " messages, with different message sizes"
        plt.title(title)
        plt.savefig("./plots/" + bench + "/message_rate/" + bench + "_" + str(msg_num) + "_fixed_num_message_rate.png")
        plt.close()

        factor = []
        for i in range(len(software_message_rate)):
            factor.append(software_message_rate[i] / hardware_message_rate[i])
        plt.plot(msg_sizes, factor, label='factor', marker='o')
        plt.xlabel("message size in bytes")
        plt.xscale("log")
        plt.ylabel("factor between software and hardware")
        plt.legend()
        title = bench + " message_rate;\n" + str(msg_num) + " messages; performance difference factor"
        plt.title(title)
        plt.savefig("./plots/" + bench + "/message_rate/" + bench + "_" + str(msg_num) + "_fixed_num_message_rate_factor.png")
        plt.close()

    for msg_size in msg_sizes:
        plt.figure()
        throughput = []
        for msg_num in msg_nums:
            throughput.append(data_software[str(msg_num)][str(msg_size)]['throughput'])
        software_throughput = throughput
        plt.plot(msg_nums, throughput, label="software", marker='o')
        throughput = []
        for msg_num in msg_nums:
            throughput.append(data_hardware[str(msg_num)][str(msg_size)]['throughput'])
        hardware_throughput = throughput
        plt.plot(msg_nums, throughput, label="hardware", marker='o')
        plt.xlabel("number of messages")
        plt.xscale("log")
        plt.ylabel("throughput in MB/s")
        plt.legend()
        title = bench + " throughput;\n" + str(msg_size) + " byte messages, with different message numbers"
        plt.title(title)
        plt.savefig("./plots/" + bench + "/throughput/" + bench + "_" + str(msg_size) + "_fixed_size_throughput.png")
        plt.close()

        factor = []
        for i in range(len(software_throughput)):
            factor.append(software_throughput[i] / hardware_throughput[i])
        plt.plot(msg_nums, factor, label='factor', marker='o')
        plt.xlabel("message number")
        plt.xscale("log")
        plt.ylabel("factor between software and hardware")
        plt.legend()
        title = bench + " throughput;\n" + str(msg_size) + " byte messages; performance difference factor"
        plt.title(title)
        plt.savefig("./plots/" + bench + "/throughput/" + bench + "_" + str(msg_num) + "_fixed_size_throughput_factor.png")
        plt.close()

        plt.figure()
        message_rate = []
        for msg_num in msg_nums:
            message_rate.append(data_software[str(msg_num)][str(msg_size)]['message_rate'])
        software_message_rate = message_rate
        plt.plot(msg_nums, message_rate, label="software", marker='o')
        message_rate = []
        for msg_num in msg_nums:
            message_rate.append(data_hardware[str(msg_num)][str(msg_size)]['message_rate'])
        hardware_message_rate = message_rate
        plt.plot(msg_nums, message_rate, label="hardware", marker='o')
        plt.xlabel("number of messages")
        plt.xscale("log")
        plt.ylabel("messages per second")
        plt.legend()
        title = bench + " message rate;\n" + str(msg_size) + " byte messages, with different message numbers"
        plt.title(title)
        plt.savefig("./plots/" + bench + "/message_rate/" + bench + "_" + str(msg_size) + "_fixed_size_message_rate.png")
        plt.close()

        factor = []
        for i in range(len(software_message_rate)):
            factor.append(software_message_rate[i] / hardware_message_rate[i])
        plt.plot(msg_nums, factor, label='factor', marker='o')
        plt.xlabel("message number")
        plt.xscale("log")
        plt.ylabel("factor between software and hardware")
        plt.legend()
        title = bench + " message_rate;\n" + str(msg_size) + " byte messages; performance difference factor"
        plt.title(title)
        plt.savefig("./plots/" + bench + "/message_rate/" + bench + "_" + str(msg_num) + "_fixed_size_message_rate_factor.png")
        plt.close()   

def main():
    create_directories()
    generate_histograms()
    for bench in benchmarks:
        data_software, data_hardware, times_software, times_hardware = organize_data(bench)
        generate_plots(bench, data_software, data_hardware)

if __name__ == "__main__":
    main()