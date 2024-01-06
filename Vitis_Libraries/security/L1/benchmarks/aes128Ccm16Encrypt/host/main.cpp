/*
 * Copyright 2019 Xilinx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <ap_int.h>
#include <iostream>
#include <fstream>

#include <sys/time.h>
#include <new>
#include <algorithm>
#include <cstdlib>

#include <xcl2.hpp>
#include "xf_utils_sw/logger.hpp"
#include "xf_security/msgpack.hpp"

#include "openssl/rand.h"


// text length for each task in 128-bit
#define N_ROW 64
// number of tasks for a single PCIe block
#define N_TASK 2 // 8192
// number of PUs
#define CH_NM 4
// cipher key size in bytes
#define KEY_SIZE 16
#define TAG_SIZE 16
#define IV_SIZE 7
#define AAD_LEN 64

class ArgParser {
   public:
    ArgParser(int& argc, const char** argv) {
        for (int i = 1; i < argc; ++i) mTokens.push_back(std::string(argv[i]));
    }
    bool getCmdOption(const std::string option, std::string& value) const {
        std::vector<std::string>::const_iterator itr;
        itr = std::find(this->mTokens.begin(), this->mTokens.end(), option);
        if (itr != this->mTokens.end() && ++itr != this->mTokens.end()) {
            value = *itr;
            return true;
        }
        return false;
    }

   private:
    std::vector<std::string> mTokens;
};

inline int tvdiff(struct timeval* tv0, struct timeval* tv1) {
    return (tv1->tv_sec - tv0->tv_sec) * 1000000 + (tv1->tv_usec - tv0->tv_usec);
}

template <typename T>
T* aligned_alloc(std::size_t num) {
    void* ptr = nullptr;
    if (posix_memalign(&ptr, 4096, num * sizeof(T))) throw std::bad_alloc();
    return reinterpret_cast<T*>(ptr);
}

void genMsg(unsigned char* ptr, uint64_t msg_len) {
    // just repeat pattern to genereate msg_len data for test
    // Any other msg will be fine too.

    const char datapattern[] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                                0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f};
    for (uint64_t i = 0; i < msg_len; i += 16) {
        memcpy(ptr + i, datapattern, 16);
    }
}

uint64_t check(unsigned char* res, unsigned char* gld, uint64_t len) {
    int num = 0;
    for (uint64_t i = 0; i < len; i++) {
        if (res[i] != gld[i]) {
            num++;
            std::cout << i << "th char not match" << std::endl;
        }
    }
    return num;
}

int main(int argc, char* argv[]) {
    // cmd parser
    ArgParser parser(argc, (const char**)argv);
    std::string xclbin_path;
    if (!parser.getCmdOption("-xclbin", xclbin_path)) {
        std::cout << "ERROR:xclbin path is not set!\n";
        return 1;
    }

    std::string msg_len_str;
    uint64_t msg_len;
    if (!parser.getCmdOption("-len", msg_len_str)) {
        std::cout << "ERROR:msg length is not set!\n";
        return 1;
    } else {
        msg_len = std::stoi(msg_len_str);
        if (msg_len % 16 != 0) {
            std::cout << "ERROR: msg length is nott multiple of 16!\n";
            return 1;
        }
        std::cout << "Length of single message is " << msg_len << " Bytes " << std::endl;
    }

    std::string msg_num_str;
    uint64_t msg_num;
    if (!parser.getCmdOption("-num", msg_num_str)) {
        std::cout << "ERROR: message number is not set!\n";
        return 1;
    } else {
        msg_num = std::stoi(msg_num_str);
        std::cout << "Message num is " << msg_num << std::endl;
    }

    std::string runs_str;
    int runs;
    if (!parser.getCmdOption("-runs", runs_str)){
        std::cout << "ERROR: number of runs is not set" << std::endl;
        return 1;
    } else {
        runs = std::stoi(runs_str);
        std::cout << "Number of runs is " << runs << std::endl;
    }

    std::string data_path;
    if(!parser.getCmdOption("-data_path", data_path)){
        std::cout << "ERROR: no path to store data" << std::endl;
        return 1;
    }

    // TODO: make the key and message random
    // cipher key for test, other keys are fine.
    std::vector<double> h2d_micro(runs, 0.0);
    std::vector<double> h2d_throughput(runs, 0.0);
    std::vector<double> kernel_micro(runs, 0.0);
    std::vector<double> kernel_throughput(runs, 0.0);
    std::vector<double> d2h_micro(runs, 0.0);
    std::vector<double> d2h_throughput(runs, 0.0);
    for(int k = 0; k < runs; k++){
        unsigned char key[KEY_SIZE];
        RAND_bytes(key, KEY_SIZE);
        std::cout << "key" << std::endl;
        std::cout << key << std::endl;

        // Additional authenticated  (equal to key)
        unsigned char aad[AAD_LEN];
        RAND_bytes(aad, AAD_LEN);
        std::cout << "aad" << std::endl;
        std::cout << aad << std::endl;

        // initialization vector for test, other IVs are fine.
        unsigned char ivec[IV_SIZE];
        RAND_bytes(ivec, IV_SIZE);
        std::cout << "ivec" << std::endl;
        std::cout << ivec << std::endl;

        // generate msg and corresponding its encrypted txt
        unsigned char* msg = (unsigned char*)malloc(msg_len + 16);
        RAND_bytes(msg, msg_len);
        std::cout << "msg" << std::endl;
        std::cout << msg << std::endl;

        // Use packer to prepare msg package.
        //
        // Package is aligned to 16Bytes.
        // Row[0] contains msg_num, and messages are stored in sequential block.
        // Each block's first row will contains its message's length, followed by IV, Key and message itself.
        // IV will take one row, Key will take two row.
        // After all messages are added, call "finishPack()" to write package header to Row[0]
        // Then no message should be added.
        //
        // Result will also be packed which is aligned to 16Bytes.
        // Row[0] contains msg_num. Messages are stored in sequential block.
        // Each block's first row will contains its message length.
        uint64_t in_pack_size = (((msg_len + 15) / 16 * 16) + ((AAD_LEN + 15) / 16 * 16) + 16 + 16 + 16 + KEY_SIZE) * msg_num + 16;
        uint64_t out_pack_size = ((msg_len + 15) / 16 * 16 + (TAG_SIZE + 15) / 16 * 16 + 16) * msg_num + 16;
        uint64_t pure_msg_size = (msg_len + 15) / 16 * 16 * msg_num;
        unsigned char* inputData = aligned_alloc<unsigned char>(in_pack_size);
        // unsigned char* inputData = (unsigned char*)malloc(in_pack_size);
        unsigned char* outputData = aligned_alloc<unsigned char>(out_pack_size);
        // unsigned char* outputData = (unsigned char*)malloc(out_pack_size);

        xf::security::internal::CcmPack<KEY_SIZE * 8, TAG_SIZE, IV_SIZE> packer;
        packer.reset();
        packer.setPtr(inputData, in_pack_size);
        for (uint64_t i = 0; i < msg_num; i++) {
            packer.addOneMsg(msg, msg_len, aad, AAD_LEN , ivec, key);
        }
        packer.finishPack();

        // CL setup
        xf::common::utils_sw::Logger logger;
        cl_int err = CL_SUCCESS;

        std::vector<cl::Device> devices = xcl::get_xil_devices();
        cl::Device device = devices[0];

        cl::Context context(device, NULL, NULL, NULL, &err);
        logger.logCreateContext(err);

        cl::CommandQueue q(context, device, CL_QUEUE_PROFILING_ENABLE | CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE, &err);
        logger.logCreateCommandQueue(err);

        std::string devName = device.getInfo<CL_DEVICE_NAME>();
        std::cout << "Selected Device " << devName << "\n";

        cl::Program::Binaries xclBins = xcl::import_binary_file(xclbin_path);
        devices.resize(1);

        cl::Program program(context, devices, xclBins, NULL, &err);
        logger.logCreateProgram(err);

        cl::Kernel kernel(program, "aes128Ccm16EncryptKernel", &err);
        logger.logCreateKernel(err);

        cl_mem_ext_ptr_t inMemExt = {0, inputData, kernel()};
        cl_mem_ext_ptr_t outMemExt = {1, outputData, kernel()};

        cl::Buffer in_buff = cl::Buffer(context, CL_MEM_EXT_PTR_XILINX | CL_MEM_USE_HOST_PTR | CL_MEM_READ_WRITE,
                                        (size_t)(in_pack_size), &inMemExt);
        cl::Buffer out_buff = cl::Buffer(context, CL_MEM_EXT_PTR_XILINX | CL_MEM_USE_HOST_PTR | CL_MEM_READ_WRITE,
                                        (size_t)(out_pack_size), &outMemExt);

        // CL buffers
        kernel.setArg(0, in_buff);
        kernel.setArg(1, out_buff);

        std::vector<cl::Memory> initBuffs;

        initBuffs.resize(0);
        initBuffs.push_back(in_buff);
        initBuffs.push_back(out_buff);

        q.enqueueMigrateMemObjects(initBuffs, 0, nullptr, nullptr);
        q.finish();

        // H2D, Kernel Execute, D2H
        std::vector<cl::Memory> inBuffs, outBuffs;

        inBuffs.resize(0);
        inBuffs.push_back(in_buff);
        outBuffs.resize(0);
        outBuffs.push_back(out_buff);
        

        std::vector<cl::Event> h2d_evts, d2h_evts, krn_evts;
        h2d_evts.resize(1);
        d2h_evts.resize(1);
        krn_evts.resize(1);
        

        q.enqueueMigrateMemObjects(inBuffs, 0, nullptr, &h2d_evts[0]);
        q.enqueueTask(kernel, &h2d_evts, &krn_evts[0]);
        q.enqueueMigrateMemObjects(outBuffs, CL_MIGRATE_MEM_OBJECT_HOST, &krn_evts, &d2h_evts[0]);
        
        q.finish();

        // Performance profiling
        unsigned long time1, time2;

        h2d_evts[0].getProfilingInfo(CL_PROFILING_COMMAND_START, &time1);
        h2d_evts[0].getProfilingInfo(CL_PROFILING_COMMAND_END, &time2);
        h2d_micro[k] = (time2 - time1) / 1000.0;
        h2d_throughput[k] = (pure_msg_size / h2d_micro[k]) / 1000.0;

        krn_evts[0].getProfilingInfo(CL_PROFILING_COMMAND_START, &time1);
        krn_evts[0].getProfilingInfo(CL_PROFILING_COMMAND_END, &time2);
        kernel_micro[k] = (time2 - time1) / 1000.0;
        kernel_throughput[k] = (pure_msg_size / kernel_micro[k]) / 1000.0;

        d2h_evts[0].getProfilingInfo(CL_PROFILING_COMMAND_START, &time1);
        d2h_evts[0].getProfilingInfo(CL_PROFILING_COMMAND_END, &time2);
        d2h_micro[k] = (time2 - time1) / 1000.0;
        d2h_throughput[k] = (pure_msg_size / d2h_micro[k]) / 1000.0;

        // release resource
        free(msg);
        free(inputData);
        free(outputData);
    }

    std::string name = "AES_128_CCM_16_encrypt_kernel";
    std::string filename = data_path + name + "_" + std::to_string(msg_num) + "_" + std::to_string(msg_len) + ".csv";
    std::cout << "store data into file " << filename << std::endl;
    std::ofstream file;
    file.open(filename);
    file << "run, time in microseconds, throughput (GB/s)\n";
    for(int k = 0; k < runs; k++){
        std::string row = std::to_string(k) + ", " + std::to_string(kernel_micro[k]) + ", " + std::to_string(kernel_throughput[k]) + "\n";
        file << row;
    }
    file.close();
    name = "AES_128_CCM_16_encrypt_h2d";
    filename = data_path + name + "_" + std::to_string(msg_num) + "_" + std::to_string(msg_len) + ".csv";
    std::cout << "store data into file " << filename << std::endl;
    file.open(filename);
    file << "run, time in microseconds, throughput (GB/s)\n";
    for(int k = 0; k < runs; k++){
        std::string row = std::to_string(k) + ", " + std::to_string(h2d_micro[k]) + ", " + std::to_string(h2d_throughput[k]) + "\n";
        file << row;
    }
    file.close();
    name = "AES_128_CCM_16_encrypt_d2h";
    filename = data_path + name + "_" + std::to_string(msg_num) + "_" + std::to_string(msg_len) + ".csv";
    std::cout << "store data into file " << filename << std::endl;
    file.open(filename);
    file << "run, time in microseconds, throughput (GB/s)\n";
    for(int k = 0; k < runs; k++){
        std::string row = std::to_string(k) + ", " + std::to_string(d2h_micro[k]) + ", " + std::to_string(d2h_throughput[k]) + "\n";
        file << row;
    }
    file.close();
}
