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

/**
 *
 * @file aes128CcmEncryptKernel.cpp
 * @brief kernel code of Cipher Block Chaining (CBC) block cipher mode of operation.
 * This file is part of Vitis Security Library.
 *
 * @detail Containing scan, distribute, encrypt, merge, and write-out functions.
 *
 */

#include <ap_int.h>
#include <hls_stream.h>
#include "xf_security/chacha20.hpp"
#include "xf_security/poly1305.hpp"
#include "xf_security/msgpack.hpp"

#include <hls_print.h>

#ifndef __SYNTHESIS
#include <iostream>
#endif

#define KEY_SIZE 32
#define TAG_SIZE 8
#define IV_SIZE 16



void ChaChaPolyWrapper(hls::stream<ap_uint<8 * KEY_SIZE> >& cipherKeyStrm,
                hls::stream<ap_uint<8 * IV_SIZE> >& counterNonceStrm,
                hls::stream<ap_uint<512> >& plainStrm,
                hls::stream <bool>& ePlainStrm,
                hls::stream <ap_uint<8 * KEY_SIZE> >& macKeyStrm,
                hls::stream <ap_uint<128> >& payloadStrm,
                hls::stream <ap_uint<64> >&lenPayloadStrm,
                hls::stream <bool>& endLenStrm,
                hls::stream<ap_uint<512> >& cipherStrm,
                hls::stream<bool>& eCipherStrm,
                hls::stream<ap_uint<128> >& tagStrm,
                ap_uint<64> msgNum) {         
    for(ap_uint<64> i = 0; i < msgNum; i++){
        xf::security::chacha20(cipherKeyStrm, counterNonceStrm, plainStrm, ePlainStrm, cipherStrm, eCipherStrm);
        xf::security::poly1305(macKeyStrm, payloadStrm, lenPayloadStrm, endLenStrm, tagStrm);
    }
}



void wrapper(ap_uint<128>* input, ap_uint<128>* output, ap_uint<64> msg_num, ap_uint<64> row_num) {
#pragma HLS dataflow

    hls::stream<ap_uint<8 * KEY_SIZE> > cipherKeyStrm("cipherKeyStrm");
#pragma HLS stream variable = cipherKeyStrm depth 4
#pragma HLS resource variable = cipherKeyStrm core = FIFO_LUTRAM

    hls::stream<ap_uint<8 * IV_SIZE> > counterNonceStrm("counterNonceStrm");
#pragma HLS stream variable = counterNonceStrm depth 4
#pragma HLS resource variable = counterNonceStrm core FIFO_LUTRAM

    hls::stream<ap_uint<512> > plainStrm("plainStrm");
#pragma HLS stream variable = plainStrm depth 32
#pragma HLS resource variable = plainStrm core FIFO_LUTRAM

    hls::stream<bool> ePlainStrm("ePlainStrm");
#pragma HLS stream variable = ePlainStrm depth 128
#pragma HLS resource variable = ePlainStrm core FIFO_LUTRAM

    hls::stream<ap_uint<8 * KEY_SIZE> > macKeyStrm("macKeyStrm");
#pragma HLS stream variable = macKeyStrm depth 4
#pragma HLS resource variable = macKeyStrm core FIFO_LUTRAM

    hls::stream<ap_uint<128> > payloadStrm("payloadStrm");
#pragma HLS stream variable = payloadStrm depth 128
#pragma HLS resource variable = payloadStrm core FIFO_LUTRAM

    hls::stream<ap_uint<64> > lenPayloadStrm("lenPayloadStrm");
#pragma HLS stream variable = lenPayloadStrm depth 4
#pragma HLS resource variable = lenPayloadStrm core FIFO_LUTRAM

    hls::stream<bool> endLenStrm("endLenStrm");
#pragma HLS stream variable = endLenStrm depth 4
#pragma HLS resource variable = endLenStrm core FIFO_LUTRAM

    xf::security::internal::ChaChaPack<8 * KEY_SIZE> packer;
    packer.scanPack(input, msg_num, row_num, cipherKeyStrm, counterNonceStrm, plainStrm, ePlainStrm, macKeyStrm, payloadStrm, lenPayloadStrm, endLenStrm);

    hls::stream<ap_uint<512> > cipherStrm("cipherStrm");
#pragma HLS stream variable = cipherStrm depth 128
#pragma HLS resouce variable = cipherStrm core FIFO_LUTRAM

    hls::stream<bool> eCipherStrm("eCipherStrm");
#pragma HLS stream variable = eCipherStrm depth 128
#pragma HLS resource variable = eCipherStrm core FIFO_LUTRAM

    hls::stream<ap_uint<128> > tagStrm("tagStrm");
#pragma HLS stream variable = tagStrm depth 128
#pragma HLS resource variable = tagStrm core FIFO_LUTRAM

    ChaChaPolyWrapper(cipherKeyStrm, counterNonceStrm, plainStrm, ePlainStrm, macKeyStrm, payloadStrm, lenPayloadStrm, endLenStrm, cipherStrm, eCipherStrm, tagStrm, msg_num);
    packer.writeOutMsgPack(output, msg_num, cipherStrm, eCipherStrm, tagStrm);
}

// @brief top of kernel
extern "C" void ChaCha20Poly1305EncryptKernel(ap_uint<128>* inputData, ap_uint<128>* outputData) {
// clang-format off
#pragma HLS INTERFACE m_axi offset = slave latency = 64 \
	num_write_outstanding = 16 num_read_outstanding = 16 \
	max_write_burst_length = 64 max_read_burst_length = 64 \
	bundle = gmem0_0 port = inputData

#pragma HLS INTERFACE m_axi offset = slave latency = 64 \
	num_write_outstanding = 16 num_read_outstanding = 16 \
	max_write_burst_length = 64 max_read_burst_length = 64 \
	bundle = gmem0_1 port = outputData
// clang-format on

#pragma HLS INTERFACE s_axilite port = inputData bundle = control
#pragma HLS INTERFACE s_axilite port = outputData bundle = control
#pragma HLS INTERFACE s_axilite port = return bundle = control

    ap_uint<128> tmp = inputData[0];
    ap_uint<64> msg_num = tmp.range(63, 0);
    ap_uint<64> row_num = tmp.range(127, 64);
    wrapper(inputData, outputData, msg_num, row_num);

} // end aes128CcmDecryptKernel
