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
#include "xf_security/cbc.hpp"
#include "xf_security/ccm.hpp"
#include "xf_security/msgpack.hpp"

#include <hls_print.h>

#ifndef __SYNTHESIS
#include <iostream>
#endif

#define KEY_SIZE 16
#define TAG_SIZE 16
#define IV_SIZE 7



void ccmWrapper(hls::stream<ap_uint<128> >&plaintext,
                hls::stream<ap_uint<8 * KEY_SIZE> >& key,
                hls::stream<ap_uint<8 * IV_SIZE> >& iv,
                hls::stream<ap_uint<128> >& aad,
                hls::stream<ap_uint<64> >& aad_len,
                hls::stream<ap_uint<64> >& msg_len,
                hls::stream <bool>& endLen,
                hls::stream<ap_uint<128> >& res,
                hls::stream<ap_uint<64> >& res_len,
                hls::stream<ap_uint<8 * TAG_SIZE> >& tag,
                hls::stream<bool>& endTag,
                ap_uint<64> msgNum) {          
    for(ap_uint<64> i = 0; i < msgNum; i++){
        xf::security::aes128CcmEncrypt<TAG_SIZE, 15 - IV_SIZE> (plaintext, key, iv, aad, aad_len, msg_len, endLen, res, res_len, tag, endTag);
    }
}



void wrapper(ap_uint<128>* input, ap_uint<128>* output, ap_uint<64> msg_num, ap_uint<64> row_num) {
#pragma HLS dataflow

    hls::stream<ap_uint<128> > textStrm("textStrm");
#pragma HLS stream variable = textStrm depth = 512
#pragma HLS resource variable = textStrm core = FIFO_LUTRAM

    hls::stream<ap_uint<128> > aadStrm("aadStrm");
#pragma HLS stream variable = aadStrm depth = 128
#pragma HLS resource variable = aadStrm core = FIFO_LUTRAM

    hls::stream<bool> endTextStrm("endTextStrm");
#pragma HLS stream variable = endTextStrm depth = 128
#pragma HLS resource variable = endTextStrm core = FIFO_LUTRAM

    hls::stream<ap_uint<128> > keyStrm("keyStrm");
#pragma HLS stream variable = keyStrm depth = 4
#pragma HLS resource variable = keyStrm core = FIFO_LUTRAM

    hls::stream<ap_uint<8 * IV_SIZE> > ivStrm("ivStrm");
#pragma HLS stream variable = ivStrm depth = 4
#pragma HLS resource variable = ivStrm core = FIFO_LUTRAM

    hls::stream<ap_uint<64> > lenMsgStrm("lenMsgStrm");
#pragma HLS stream variable = lenMsgStrm depth = 4
#pragma HLS resource variable = lenMsgStrm core = FIFO_LUTRAM

    hls::stream<ap_uint<64> > lenAadStrm("lenAadStrm");
#pragma HLS stream variable = lenAadStrm depth = 4
#pragma HLS resource variable = lenAadStrm core = FIFO_LUTRAM

    xf::security::internal::CcmPack<8 * KEY_SIZE, TAG_SIZE, IV_SIZE> packer;
    packer.scanPack(input, msg_num, row_num, textStrm, aadStrm, endTextStrm, keyStrm, ivStrm, lenMsgStrm, lenAadStrm);
    hls::stream<ap_uint<128> > resStrm("resStrm");
#pragma HLS stream variable = resStrm depth = 128
#pragma HLS resource variable = resStrm core = FIFO_LUTRAM

    hls::stream<ap_uint<64> > lenResStrm("lenResStrm");
#pragma HLS stream variable = lenResStrm depth = 4
#pragma HLS resource variable = lenResStrm core = FIFO_LUTRAM

    hls::stream<ap_uint<8 * TAG_SIZE> > tagStrm("tagStrm");
#pragma HLS stream variable = tagStrm  depth = 128
#pragma HLS resource variable = tagStrm core = FIFO_LUTRAM

    hls::stream<bool> endTagStrm("endTagStrm");
#pragma HLS stream variable = endTagStrm depth = 128
#pragma HLS resource variable = endTagStrm core = FIFO_LUTRAM

    ccmWrapper(textStrm, keyStrm, ivStrm, aadStrm, lenAadStrm, lenMsgStrm, endTextStrm, resStrm, lenResStrm, tagStrm, endTagStrm, msg_num);
    packer.writeOutMsgPack(output, msg_num, resStrm, tagStrm, endTagStrm, lenResStrm);
}

// @brief top of kernel
extern "C" void aes128Ccm16EncryptKernel(ap_uint<128>* inputData, ap_uint<128>* outputData) {
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
