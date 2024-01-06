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

#include <sys/time.h>
#include <new>
#include <cstdlib>
#include <xcl2.hpp>
#include <cstdint>

#include "xf_utils_sw/logger.hpp"
#include "xf_utils_sw/arg_parser.hpp"

// number of bytes to be transfered in each channel.
// SIZE is expected to be a multiple of 4 as the
// minimum size of data port width is 32-bit,
// otherwise, out-of-boundary data would be
// transfered in and out.
#define SIZE 1024
// width of channel 1, in bits
#define WIDTH_CH1 128

inline int tvdiff(struct timeval* tv0, struct timeval* tv1) {
    return (tv1->tv_sec - tv0->tv_sec) * 1000000 + (tv1->tv_usec - tv0->tv_usec);
}

template <typename T>
T* aligned_alloc(std::size_t num) {
    void* ptr = nullptr;
    if (posix_memalign(&ptr, 4096, num * sizeof(T))) throw std::bad_alloc();
    return reinterpret_cast<T*>(ptr);
}

int main(int argc, const char* argv[]) {
    using namespace xf::common::utils_sw;
    Logger logger;
    ArgParser parser(argc, argv);
    parser.addOption("", "--xclbin", "xclbin path", "", true);
    std::string xclbin_path = parser.getAs<std::string>("xclbin");

    std::cout << "Starting test.\n";

    // input buffer considered as golden for the output
    char golden1[SIZE];
    unsigned int seed = 12;
    srand(seed);
    for (int i = 0; i < SIZE; i++) {
        golden1[i] = rand() & 0xffUL;
    }

    const int nBlks1 = SIZE / (WIDTH_CH1 / 8);
    // Host buffers
    ap_uint<WIDTH_CH1>* hb_in1 = aligned_alloc<ap_uint<WIDTH_CH1> >(nBlks1);
    ap_uint<WIDTH_CH1>* hb_out1 = aligned_alloc<ap_uint<WIDTH_CH1> >(nBlks1);

    // set input & reset output buffer of each channel
    for (unsigned int j = 0; j < SIZE; j++) {
        hb_in1[j / (WIDTH_CH1 / 8)].range((j % (WIDTH_CH1 / 8)) * 8 + 7, (j % (WIDTH_CH1 / 8)) * 8) = golden1[j];
        hb_out1[j / (WIDTH_CH1 / 8)].range((j % (WIDTH_CH1 / 8)) * 8 + 7, (j % (WIDTH_CH1 / 8)) * 8) = 0;
    }

    std::cout << "Host map buffer has been allocated and set.\n";

    // Get CL devices.
    std::vector<cl::Device> devices = xcl::get_xil_devices();
    cl::Device device = devices[0];
    std::string devName = device.getInfo<CL_DEVICE_NAME>();
    std::cout << "Selected Device " << devName << "\n";

    // Create context and command queue for selected device
    cl_int err;
    cl::Context context(device, nullptr, nullptr, nullptr, &err);
    logger.logCreateContext(err);
    cl::CommandQueue q(context, device, CL_QUEUE_PROFILING_ENABLE | CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE, &err);
    logger.logCreateCommandQueue(err);

    cl::Program::Binaries xclBins = xcl::import_binary_file(xclbin_path);
    devices.resize(1);
    cl::Program program(context, devices, xclBins, nullptr, &err);
    logger.logCreateProgram(err);

    cl::Kernel kernel0(program, "m2s_x1", &err);
    logger.logCreateKernel(err);
    cl::Kernel kernel1(program, "s2m_x1", &err);
    logger.logCreateKernel(err);

    cl_mem_ext_ptr_t mext_ch1[2];
    mext_ch1[0] = {0, hb_in1, kernel0()};
    mext_ch1[1] = {1, hb_out1, kernel1()};

    cl::Buffer ch1_buff[2];

    // Map buffers
    for (int i = 0; i < 2; i++) {
        ch1_buff[i] = cl::Buffer(context, CL_MEM_EXT_PTR_XILINX | CL_MEM_USE_HOST_PTR | CL_MEM_READ_ONLY, (size_t)SIZE,
                                 &mext_ch1[i]);
    }

    std::cout << "DDR buffers have been mapped/copy-and-mapped\n";

    q.finish();

    struct timeval start_time, end_time;
    gettimeofday(&start_time, 0);

    std::vector<std::vector<cl::Event> > write_events(1);
    std::vector<std::vector<cl::Event> > kernel_events(1);
    std::vector<std::vector<cl::Event> > read_events(1);
    write_events[0].resize(1);
    kernel_events[0].resize(2);
    read_events[0].resize(1);

    // write data to DDR
    std::vector<cl::Memory> ib;
    ib.push_back(ch1_buff[0]);

    q.enqueueMigrateMemObjects(ib, 0, nullptr, &write_events[0][0]);

    // set args and enqueue kernel
    kernel0.setArg(0, ch1_buff[0]);
    kernel0.setArg(2, (uint64_t)SIZE);
    kernel1.setArg(1, ch1_buff[1]);
    kernel1.setArg(2, (uint64_t)SIZE);
    q.enqueueTask(kernel0, &write_events[0], &kernel_events[0][0]);
    q.enqueueTask(kernel1, &write_events[0], &kernel_events[0][1]);

    // read data from DDR
    std::vector<cl::Memory> ob;
    ob.push_back(ch1_buff[1]);
    q.enqueueMigrateMemObjects(ob, CL_MIGRATE_MEM_OBJECT_HOST, &kernel_events[0], &read_events[0][0]);

    // wait all to finish
    q.flush();
    q.finish();
    gettimeofday(&end_time, 0);
    std::cout << "Execution time " << tvdiff(&start_time, &end_time) << "us" << std::endl;

    // check result
    int nerror1 = 0;
    for (int i = 0; i < nBlks1; i++) {
        if (hb_in1[i] != hb_out1[i]) {
            nerror1++;
            std::cout << std::hex << "Error " << i << ": hb_in = " << hb_in1[i] << ", hb_out = " << hb_out1[i]
                      << std::endl;
        }
    }

    if (nerror1) {
        std::cout << "Found " << nerror1 << " errors in channel-1." << std::endl;
        logger.error(Logger::Message::TEST_FAIL);
    } else {
        std::cout << "No error found in " << SIZE << " bytes of input in each channel." << std::endl;
        logger.info(Logger::Message::TEST_PASS);
    }
    return nerror1;
}
