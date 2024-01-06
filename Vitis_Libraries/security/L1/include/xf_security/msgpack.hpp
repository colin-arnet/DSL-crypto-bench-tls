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
 * @file aes.hpp
 * @brief header file for Advanced Encryption Standard relate function.
 * This file part of Vitis Security Library.
 *
 * @detail Currently we have Aes256_Encryption for AES256 standard.
 */

#ifndef _XF_SECURITY_MSG_PACK_HPP_
#define _XF_SECURITY_MSG_PACK_HPP_

#include <hls_print.h>

#include <ap_int.h>
#include <stdint.h>
#include <hls_stream.h>
#ifndef __SYNTHESIS__
#include <iostream>
#endif
namespace xf {
namespace security {
namespace internal {

/**
 * @brief Base class of msg packer
 *
 * @tparam W Bit width of one row. Support 64, 128, 256, 512.
 */
template <int W>
class packBase {
   public:
    int64_t msg_num;
    int64_t curr_ptr; // not in bytes, in rows

    int64_t buffer_size; // in bytes
    int64_t total_row;
    unsigned char* buffer_ptr;

    bool isReset;
    bool isMemAlloced;

    packBase() {
#pragma HLS inline
#ifndef __SYNTHESIS__
        isReset = false;
        isMemAlloced = false;
#endif
    }

    /**
     * @brief Reset records for packBase, need to be called each time a new pack to be process. reset function won't
     * release any alloced memory. Should only be used on host side.
     */
    void reset() {
        msg_num = 0;
        if (W == 64) {
            curr_ptr = 2;
        } else if (W == 128) {
            curr_ptr = 1;
        } else if (W == 256) {
            curr_ptr = 1;
        } else if (W == 512) {
            curr_ptr = 1;
        } else {
#ifndef __SYNTHESIS__
            std::cout << W << " bits width of row is not supported. Only 64 / 128 / 256 / 512 is allowed." << std::endl;
#endif
        }

        buffer_size = 0;
        buffer_ptr = nullptr;

        isReset = true;
        isMemAlloced = false;
    }
    /**
     * @brief Assign alloced memory to packBase to process. Should only be used on host side.
     *
     * @param ptr Pointer to allocated memory.
     * @size Size of allocated memory.
     */
    void setPtr(unsigned char* ptr, int64_t size) {
        buffer_ptr = ptr;
        buffer_size = size;
        total_row = buffer_size / (W / 8);

        isMemAlloced = true;
    }

    /**
     * @brief Finish a pack by adding number of message and effective rows of pack. This funciton need to be called once
     * before send the package for processing. Should only be used on host side.
     *
     * @param ptr Pointer to allocated memory.
     * @size Size of allocated memory.
     */
    void finishPack() {
        int64_t* header = (int64_t*)buffer_ptr;
        header[0] = msg_num;
        header[1] = curr_ptr;
    }
};

// CBC PACKER
/**
 * @brief Base class of msg packer. Bit width of one row is 128.
 *
 * @tparam KeyW Bit width of key, only support 128, 192, 256
 */
template <int KeyW>
class aesCbcPack : public packBase<128> {
   private:
    void scanRaw(ap_uint<128>* ddr, ap_uint<64> row_num, hls::stream<ap_uint<128> >& rawStrm) {
        for (ap_uint<64> i = 1; i < row_num; i++) {
#pragma HLS pipeline II = 1
            ap_uint<128> tmp = ddr[i];
            rawStrm.write(tmp);
        }
    }

    void parsePack(ap_uint<64> msg_num,
                   hls::stream<ap_uint<128> >& rawStrm,
                   hls::stream<ap_uint<128> >& textStrm,
                   hls::stream<bool>& endTextStrm,
                   hls::stream<ap_uint<KeyW> >& keyStrm,
                   hls::stream<ap_uint<128> >& IVStrm,
                   hls::stream<ap_uint<64> >& lenStrm) {
        for (ap_uint<64> i = 0; i < msg_num; i++) {
            ap_uint<64> len = rawStrm.read();
            ap_uint<128> iv = rawStrm.read();
            ap_uint<128> keyL = rawStrm.read();
            ap_uint<128> keyH = 0;
            ap_uint<KeyW> key = 0;
            if (KeyW > 128) {
                keyH = rawStrm.read();
            }
            key.range(127, 0) = keyL;
            key.range(KeyW - 1, 128) = keyH.range(KeyW - 129, 0);
            keyStrm.write(key);
            IVStrm.write(iv);
            lenStrm.write(len);
            for (ap_uint<64> i = 0; i < len; i += 16) {
#pragma HLS pipeline II = 1
                textStrm.write(rawStrm.read());
                endTextStrm.write(false);
            }
            endTextStrm.write(true);
        }
    }

    void writeRaw(ap_uint<128>* ddr, hls::stream<ap_uint<128> >& rawStrm, hls::stream<ap_uint<16> >& numRawStrm) {
        ap_uint<64> addr = 0;
        ap_uint<16> numRaw = numRawStrm.read();
        while (numRaw != 0) {
            for (ap_uint<16> i = 0; i < numRaw; i++) {
#pragma HLS pipeline II = 1
                ddr[addr + i] = rawStrm.read();
            }
            addr += numRaw;
            numRaw = numRawStrm.read();
        }
    }

    void preparePack(ap_uint<64> msg_num,
                     hls::stream<ap_uint<128> >& textStrm,
                     hls::stream<bool>& endTextStrm,
                     hls::stream<ap_uint<64> >& lenStrm,
                     hls::stream<ap_uint<128> >& rawStrm,
                     hls::stream<ap_uint<16> >& numRawStrm) {
        ap_uint<16> numRaw = 0;

        rawStrm.write(ap_uint<128>(msg_num));
        numRaw++;
        for (ap_uint<64> i = 0; i < msg_num; i++) {
            ap_uint<64> length = lenStrm.read();
            rawStrm.write(ap_uint<128>(length));
            numRaw++;
            if (numRaw == 64) {
                numRaw = 0;
                numRawStrm.write(ap_uint<16>(64));
            }
            while (!endTextStrm.read()) {
                rawStrm.write(textStrm.read());
                numRaw++;
                if (numRaw == 64) {
                    numRaw = 0;
                    numRawStrm.write(ap_uint<16>(64));
                }
            }
        }
        if (numRaw != 0) {
            numRawStrm.write(numRaw);
        }
        numRawStrm.write(0);
    }

   public:
    aesCbcPack() {
#pragma HLS inline
    }

#ifndef __SYNTHESIS__
    /**
     * @brief Add one message.
     *
     * @msg Pointer of message to be added.
     * @len Length of message to be added.
     * @iv Initialization vector of this message.
     * @key Encryption key
     * @return return true if successfully add message, other wise false.
     */
    bool addOneMsg(unsigned char* msg, int64_t len, unsigned char* iv, unsigned char* key) {
        if (!isReset) {
            std::cout << "Not reset yet, please call reset()" << std::endl;
            return false;
        }
        if (!isMemAlloced) {
            std::cout << "Memory not alloced yet, please call setPtr()" << std::endl;
            return false;
        }

        int64_t row_inc = 1 + 1 + (len + 15) / 16; // 1 for len, 1 for iv, 1 or 2 for key, (len + 15) / 16 for msg;
        if (KeyW > 128) {
            row_inc += 2;
        } else {
            row_inc += 1;
        }

        if (curr_ptr + row_inc > total_row) {
            std::cout << "Memory left not enough to add one message" << std::endl;
            return false;
        }

        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        *(int64_t*)(buffer_ptr + (curr_ptr * 16)) = len;
        curr_ptr++;

        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)iv, 16);
        curr_ptr++;

        if (KeyW > 128) {
            memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 32);
        } else {
            memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        }
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)key, KeyW / 8);
        if (KeyW > 128) {
            curr_ptr += 2;
        } else {
            curr_ptr += 1;
        }

        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, (len + 15) / 16 * 16);
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)msg, len);
        curr_ptr += (len + 15) / 16;
        msg_num++;
        return true;
    }
#endif

    void scanPack(ap_uint<128>* ddr,
                  ap_uint<64> msg_num,
                  ap_uint<64> row_num,
                  hls::stream<ap_uint<128> >& textStrm,
                  hls::stream<bool>& endTextStrm,
                  hls::stream<ap_uint<KeyW> >& keyStrm,
                  hls::stream<ap_uint<128> >& IVStrm,
                  hls::stream<ap_uint<64> >& lenStrm) {
#pragma HLS dataflow
        hls::stream<ap_uint<128> > rawStrm;
#pragma HLS stream variable = rawStrm depth = 128
        scanRaw(ddr, row_num, rawStrm);
        parsePack(msg_num, rawStrm, textStrm, endTextStrm, keyStrm, IVStrm, lenStrm);
    }

    void writeOutMsgPack(ap_uint<128>* ddr,
                         ap_uint<64> msg_num,
                         hls::stream<ap_uint<128> >& textStrm,
                         hls::stream<bool>& endTextStrm,
                         hls::stream<ap_uint<64> >& lenStrm) {
#pragma HLS dataflow
        hls::stream<ap_uint<128> > rawStrm;
#pragma HLS stream variable = rawStrm depth = 128
        hls::stream<ap_uint<16> > numRawStrm;
#pragma HLS stream variable = numRawStrm depth = 4
        
        preparePack(msg_num, textStrm, endTextStrm, lenStrm, rawStrm, numRawStrm);
        writeRaw(ddr, rawStrm, numRawStrm);
    }
};

// GCM PACKER
/**
 * @brief Base class of msg packer. Bit width of one row is 128.
 *
 * @tparam KeyW Bit width of key, only support 128, 192, 256
 */
template <int KeyW>
class GcmPack : public packBase<128> {
   private:
    void scanRaw(ap_uint<128>* ddr, ap_uint<64> row_num, hls::stream<ap_uint<128> >& rawStrm) {
        for (ap_uint<64> i = 1; i < row_num; i++) {
#pragma HLS pipeline II = 1
            ap_uint<128> tmp = ddr[i];
            rawStrm.write(tmp);
        }
    }

    void parsePack(ap_uint<64> msg_num,
                   hls::stream<ap_uint<128> >& rawStrm,
                   hls::stream<ap_uint<128> >& textStrm,
                   hls::stream<ap_uint<128> >& aadStrm,
                   hls::stream<bool>& endTextStrm,
                   hls::stream<ap_uint<KeyW> >& keyStrm,
                   hls::stream<ap_uint<96> >& IVStrm,
                   hls::stream<ap_uint<64> >& lenMsgStrm,
                   hls::stream<ap_uint<64> >& lenAadStrm) {
        // serialized message format:
        // msg_len, aad_len, iv, key, msg, aad
        for (ap_uint<64> i = 0; i < msg_num; i++) {
            ap_uint<64> msg_len = rawStrm.read();
            ap_uint<64> aad_len = rawStrm.read();
            ap_uint<96> iv = rawStrm.read();
            ap_uint<128> keyL = rawStrm.read();
            ap_uint<128> keyH = 0;
            ap_uint<KeyW> key = 0;
            if (KeyW > 128) {
                keyH = rawStrm.read();
            }
            key.range(127, 0) = keyL;
            if(KeyW > 128){
                key.range(KeyW - 1, 128) = keyH.range(KeyW - 129, 0);
            }
            keyStrm.write(key);
            IVStrm.write(iv);
            lenMsgStrm.write(msg_len * 8);
            lenAadStrm.write(aad_len * 8);
            // read aad and write to aad_stream
            for (ap_uint<64> i = 0; i < aad_len; i += 16) {
#pragma HLS pipeline II = 1
                ap_uint<128> aad_part = rawStrm.read();
                aadStrm.write(aad_part);
            }
            // read msg and write to msg_stream
            for (ap_uint<64> i = 0; i < msg_len; i += 16) {
#pragma HLS pipeline II = 1
                ap_uint<128> msg_part = rawStrm.read();
                textStrm.write(msg_part);
            }
            endTextStrm.write(false);
            endTextStrm.write(true);
            }
        }

    void writeRaw(ap_uint<128>* ddr, hls::stream<ap_uint<128> >& rawStrm, hls::stream<ap_uint<16> >& numRawStrm) {
        ap_uint<64> addr = 0;
        ap_uint<16> numRaw = numRawStrm.read();
        while (numRaw != 0) {
            for (ap_uint<16> i = 0; i < numRaw; i++) {
#pragma HLS pipeline II = 1
                ddr[addr + i] = rawStrm.read();
            }
            addr += numRaw;
            numRaw = numRawStrm.read();
        }
    }

    // out packet format:
    // msg_len, ciphertext, tag
    void preparePack(ap_uint<64> msg_num,
                     hls::stream<ap_uint<128> >& textStrm,
                     hls::stream<ap_uint<128> >& tagStrm,
                     hls::stream<bool>& endTagStrm,
                     hls::stream<ap_uint<64> >& lenStrm,
                     hls::stream<ap_uint<128> >& rawStrm,
                     hls::stream<ap_uint<16> >& numRawStrm) {
        ap_uint<16> numRaw = 0;

        rawStrm.write(ap_uint<128>(msg_num));
        numRaw++;
        for (ap_uint<64> i = 0; i < msg_num; i++) {
            ap_uint<64> msg_len = lenStrm.read();
            rawStrm.write(ap_uint<128>(msg_len));
            numRaw++;
            if (numRaw == 64) {
                numRaw = 0;
                numRawStrm.write(ap_uint<16>(64));
            }
            for(ap_uint<64> k = 0; k < msg_len; k += 128){
                rawStrm.write(textStrm.read());
                numRaw++;
                if (numRaw == 64) {
                    numRaw = 0;
                    numRawStrm.write(ap_uint<16>(64));
                }
            }
            while (!endTagStrm.read()) {
                rawStrm.write(tagStrm.read());
                numRaw++;
                if (numRaw == 64) {
                    numRaw = 0;
                    numRawStrm.write(ap_uint<16>(64));
                }
            }
        }
        if (numRaw != 0) {
            numRawStrm.write(numRaw);
        }
        numRawStrm.write(0);
    }

   public:
    GcmPack() {
#pragma HLS inline
    }

#ifndef __SYNTHESIS__
    /**
     * @brief Add one message.
     *
     * @msg Pointer of message to be added.
     * @len Length of message to be added.
     * @iv Initialization vector of this message.
     * @key Encryption key
     * @return return true if successfully add message, other wise false.
     */

    // message is serialized:
    // Format:
    // msg_len, aad_len, iv, key, aad (optional), msg
    bool addOneMsg(unsigned char* msg, int64_t len, unsigned char* aad, int64_t aad_len, unsigned char* iv, unsigned char* key) {
        if (!isReset) {
            std::cout << "Not reset yet, please call reset()" << std::endl;
            return false;
        }
        if (!isMemAlloced) {
            std::cout << "Memory not alloced yet, please call setPtr()" << std::endl;
            return false;
        }

        // row_inc: 1 for len, 1 for aad_len, 1 for iv, aad, msg, 1 or 2 for key
        int64_t row_inc = 1 + 1 + 1 + (aad_len + 15) / 16 + (len + 15) / 16;
        if (KeyW > 128) {
            row_inc += 2;
        } else {
            row_inc += 1;
        }

        if (curr_ptr + row_inc > total_row) {
            std::cout << "Memory left not enough to add one message" << std::endl;
            return false;
        }

        // set msg length
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        *(int64_t*)(buffer_ptr + (curr_ptr * 16)) = len;
        curr_ptr++;

        // set aad length if 0 no aad will be set
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        *(int64_t*)(buffer_ptr + (curr_ptr * 16)) = aad_len;
        curr_ptr++;

        // set iv
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)iv, 16);
        curr_ptr++;

        // set key (2 rows for large keys)
        if (KeyW > 128) {
            memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 32);
        } else {
            memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        }
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)key, KeyW / 8);
        if (KeyW > 128) {
            curr_ptr += 2;
        } else {
            curr_ptr += 1;
        }

        // set aad (optional)
        if (aad_len > 0){
            memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, (aad_len + 15) / 16 * 16);
            memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)aad, aad_len);
            curr_ptr += (aad_len + 15) / 16;
        }

        // set msg
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, (len + 15) / 16 * 16);
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)msg, len);
        curr_ptr += (len + 15) / 16;

        msg_num++;
        return true;
    }
#endif

    void scanPack(ap_uint<128>* ddr,
                  ap_uint<64> msg_num,
                  ap_uint<64> row_num,
                  hls::stream<ap_uint<128> >& textStrm,
                  hls::stream<ap_uint<128> >& aadStrm,
                  hls::stream<bool>& endTextStrm,
                  hls::stream<ap_uint<KeyW> >& keyStrm,
                  hls::stream<ap_uint<96> >& IVStrm,
                  hls::stream<ap_uint<64> >& lenMsgStrm,
                  hls::stream<ap_uint<64> >& lenAadStrm) {
#pragma HLS dataflow
        hls::stream<ap_uint<128> > rawStrm;
#pragma HLS stream variable = rawStrm depth = 128
        scanRaw(ddr, row_num, rawStrm);
        parsePack(msg_num, rawStrm, textStrm, aadStrm, endTextStrm, keyStrm, IVStrm, lenMsgStrm, lenAadStrm);
    }

    void writeOutMsgPack(ap_uint<128>* ddr,
                         ap_uint<64> msg_num,
                         hls::stream<ap_uint<128> >& textStrm,
                         hls::stream<ap_uint<128> >& tagStrm,
                         hls::stream<bool>& endTagStrm,
                         hls::stream<ap_uint<64> >& lenStrm) {
#pragma HLS dataflow
        hls::stream<ap_uint<128> > rawStrm;
#pragma HLS stream variable = rawStrm depth = 128
        hls::stream<ap_uint<16> > numRawStrm;
#pragma HLS stream variable = numRawStrm depth = 4
        preparePack(msg_num, textStrm, tagStrm, endTagStrm, lenStrm, rawStrm, numRawStrm);
        writeRaw(ddr, rawStrm, numRawStrm);
    }
};

// CCM PACKER
/**
 * @brief Base class of msg packer. Bit width of one row is 128.
 *
 * @tparam KeyW Bit width of key, only support 128, 192, 256
 */
template <int KeyW, int TAG_SIZE, int IV_SIZE>
class CcmPack : public packBase<128> {
   private:
    void scanRaw(ap_uint<128>* ddr, ap_uint<64> row_num, hls::stream<ap_uint<128> >& rawStrm) {
        for (ap_uint<64> i = 1; i < row_num; i++) {
#pragma HLS pipeline II = 1
            ap_uint<128> tmp = ddr[i];
            rawStrm.write(tmp);
        }
    }

    void parsePack(ap_uint<64> msg_num,
                   hls::stream<ap_uint<128> >& rawStrm,
                   hls::stream<ap_uint<128> >& textStrm,
                   hls::stream<ap_uint<128> >& aadStrm,
                   hls::stream<bool>& endTextStrm,
                   hls::stream<ap_uint<KeyW> >& keyStrm,
                   hls::stream<ap_uint<8 * IV_SIZE> >& IVStrm,
                   hls::stream<ap_uint<64> >& lenMsgStrm,
                   hls::stream<ap_uint<64> >& lenAadStrm) {
        // serialized message format:
        // msg_len, aad_len, iv, key, msg, aad
        for (ap_uint<64> i = 0; i < msg_num; i++) {
            ap_uint<64> msg_len = rawStrm.read();
            ap_uint<64> aad_len = rawStrm.read();
            ap_uint<8 * IV_SIZE> iv = rawStrm.read();
            ap_uint<128> keyL = rawStrm.read();
            ap_uint<128> keyH = 0;
            ap_uint<KeyW> key = 0;
            if (KeyW > 128) {
                keyH = rawStrm.read();
            }
            key.range(127, 0) = keyL;
            if(KeyW > 128){
                key.range(KeyW - 1, 128) = keyH.range(KeyW - 129, 0);
            }
            keyStrm.write(key);
            IVStrm.write(iv);
            lenMsgStrm.write(msg_len);
            lenAadStrm.write(aad_len);
            // read aad and write to aad_stream
            for (ap_uint<64> i = 0; i < aad_len; i += 16) {
#pragma HLS pipeline II = 1
                ap_uint<128> aad_part = rawStrm.read();
                aadStrm.write(aad_part);
            }
            // read msg and write to msg_stream
            for (ap_uint<64> i = 0; i < msg_len; i += 16) {
#pragma HLS pipeline II = 1
                ap_uint<128> msg_part = rawStrm.read();
                textStrm.write(msg_part);
            }
            endTextStrm.write(false);
            endTextStrm.write(true);
            }
        }

    void writeRaw(ap_uint<128>* ddr, hls::stream<ap_uint<128> >& rawStrm, hls::stream<ap_uint<16> >& numRawStrm) {
        ap_uint<64> addr = 0;
        ap_uint<16> numRaw = numRawStrm.read();
        while (numRaw != 0) {
            for (ap_uint<16> i = 0; i < numRaw; i++) {
#pragma HLS pipeline II = 1
                ddr[addr + i] = rawStrm.read();
            }
            addr += numRaw;
            numRaw = numRawStrm.read();
        }
    }

    // out packet format:
    // msg_len, ciphertext, tag
    void preparePack(ap_uint<64> msg_num,
                     hls::stream<ap_uint<128> >& textStrm,
                     hls::stream<ap_uint<8 * TAG_SIZE> >& tagStrm,
                     hls::stream<bool>& endTagStrm,
                     hls::stream<ap_uint<64> >& lenStrm,
                     hls::stream<ap_uint<128> >& rawStrm,
                     hls::stream<ap_uint<16> >& numRawStrm) {
        ap_uint<16> numRaw = 0;

        rawStrm.write(ap_uint<128>(msg_num));
        numRaw++;
        for (ap_uint<64> i = 0; i < msg_num; i++) {
            ap_uint<64> msg_len = lenStrm.read();
            rawStrm.write(ap_uint<128>(msg_len));
            numRaw++;
            if (numRaw == 64) {
                numRaw = 0;
                numRawStrm.write(ap_uint<16>(64));
            }
            for(ap_uint<64> k = 0; k < msg_len; k += 16){
                rawStrm.write(textStrm.read());
                numRaw++;
                if (numRaw == 64) {
                    numRaw = 0;
                    numRawStrm.write(ap_uint<16>(64));
                }
            }
            while (!endTagStrm.read()) {
                rawStrm.write(tagStrm.read());
                numRaw++;
                if (numRaw == 64) {
                    numRaw = 0;
                    numRawStrm.write(ap_uint<16>(64));
                }
            }
        }
        if (numRaw != 0) {
            numRawStrm.write(numRaw);
        }
        numRawStrm.write(0);
    }

   public:
    CcmPack() {
#pragma HLS inline
    }

#ifndef __SYNTHESIS__
    /**
     * @brief Add one message.
     *
     * @msg Pointer of message to be added.
     * @len Length of message to be added.
     * @iv Initialization vector of this message.
     * @key Encryption key
     * @return return true if successfully add message, other wise false.
     */

    // message is serialized:
    // Format:
    // msg_len, aad_len, iv, key, aad (optional), msg
    bool addOneMsg(unsigned char* msg, int64_t len, unsigned char* aad, int64_t aad_len, unsigned char* iv, unsigned char* key) {
        if (!isReset) {
            std::cout << "Not reset yet, please call reset()" << std::endl;
            return false;
        }
        if (!isMemAlloced) {
            std::cout << "Memory not alloced yet, please call setPtr()" << std::endl;
            return false;
        }

        // row_inc: 1 for len, 1 for aad_len, 1 for iv, aad, msg, 1 or 2 for key
        int64_t row_inc = 1 + 1 + 1 + (aad_len + 15) / 16 + (len + 15) / 16;
        if (KeyW > 128) {
            row_inc += 2;
        } else {
            row_inc += 1;
        }

        if (curr_ptr + row_inc > total_row) {
            std::cout << "Memory left not enough to add one message" << std::endl;
            return false;
        }

        // set msg length
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        *(int64_t*)(buffer_ptr + (curr_ptr * 16)) = len;
        curr_ptr++;

        // set aad length if 0 no aad will be set
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        *(int64_t*)(buffer_ptr + (curr_ptr * 16)) = aad_len;
        curr_ptr++;

        // set iv
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)iv, 16);
        curr_ptr++;

        // set key (2 rows for large keys)
        if (KeyW > 128) {
            memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 32);
        } else {
            memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        }
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)key, KeyW / 8);
        if (KeyW > 128) {
            curr_ptr += 2;
        } else {
            curr_ptr += 1;
        }

        // set aad (optional)
        if (aad_len > 0){
            memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, (aad_len + 15) / 16 * 16);
            memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)aad, aad_len);
            curr_ptr += (aad_len + 15) / 16;
        }

        // set msg
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, (len + 15) / 16 * 16);
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)msg, len);
        curr_ptr += (len + 15) / 16;

        msg_num++;
        return true;
    }
#endif

    void scanPack(ap_uint<128>* ddr,
                  ap_uint<64> msg_num,
                  ap_uint<64> row_num,
                  hls::stream<ap_uint<128> >& textStrm,
                  hls::stream<ap_uint<128> >& aadStrm,
                  hls::stream<bool>& endTextStrm,
                  hls::stream<ap_uint<KeyW> >& keyStrm,
                  hls::stream<ap_uint<8 * IV_SIZE> >& IVStrm,
                  hls::stream<ap_uint<64> >& lenMsgStrm,
                  hls::stream<ap_uint<64> >& lenAadStrm) {
#pragma HLS dataflow
        hls::stream<ap_uint<128> > rawStrm;
#pragma HLS stream variable = rawStrm depth = 128
        scanRaw(ddr, row_num, rawStrm);
        parsePack(msg_num, rawStrm, textStrm, aadStrm, endTextStrm, keyStrm, IVStrm, lenMsgStrm, lenAadStrm);
    }

    void writeOutMsgPack(ap_uint<128>* ddr,
                         ap_uint<64> msg_num,
                         hls::stream<ap_uint<128> >& textStrm,
                         hls::stream<ap_uint<8 * TAG_SIZE> >& tagStrm,
                         hls::stream<bool>& endTagStrm,
                         hls::stream<ap_uint<64> >& lenStrm) {
#pragma HLS dataflow
        hls::stream<ap_uint<128> > rawStrm;
#pragma HLS stream variable = rawStrm depth = 128
        hls::stream<ap_uint<16> > numRawStrm;
#pragma HLS stream variable = numRawStrm depth = 4
        preparePack(msg_num, textStrm, tagStrm, endTagStrm, lenStrm, rawStrm, numRawStrm);
        writeRaw(ddr, rawStrm, numRawStrm);
    }
};

// ChaCha PACKER
/**
 * @brief Base class of msg packer. Bit width of one row is 128.
 *
 * @tparam KeyW Bit width of key, only support 128, 192, 256
 */
template <int KeyW>
class ChaChaPack : public packBase<128> {
   private:
    void scanRaw(ap_uint<128>* ddr, ap_uint<64> row_num, hls::stream<ap_uint<128> >& rawStrm) {
        for (ap_uint<64> i = 1; i < row_num; i++) {
#pragma HLS pipeline II = 1
            ap_uint<128> tmp = ddr[i];
            rawStrm.write(tmp);
        }
    }

    void parsePack(ap_uint<64> msg_num,
                   hls::stream<ap_uint<128> >& rawStrm,
                   hls::stream<ap_uint<KeyW> >& cipherKeyStrm,
                   hls::stream<ap_uint<128> >& counterNonceStrm,
                   hls::stream<ap_uint<512> >& plainStrm,
                   hls::stream<bool>& ePlainStrm,
                   hls::stream<ap_uint<KeyW> >& macKeyStrm,
                   hls::stream<ap_uint<128> >& payloadStrm,
                   hls::stream<ap_uint<64> >& lenPayloadStrm,
                   hls::stream<bool>& endLenStrm) {
        // serialized message format:
        // msg_len, aad_len, iv, key, msg, aad
        for (ap_uint<64> i = 0; i < msg_num; i++) {
            ap_uint<64> msg_len = rawStrm.read();
            ap_uint<128> iv = rawStrm.read();
            ap_uint<128> keyL = rawStrm.read();
            ap_uint<128> keyH = 0;
            ap_uint<KeyW> key = 0;
            if (KeyW > 128) {
                keyH = rawStrm.read();
            }
            key.range(127, 0) = keyL;
            if(KeyW > 128){
                key.range(KeyW - 1, 128) = keyH.range(KeyW - 129, 0);
            }
            cipherKeyStrm.write(key);
            macKeyStrm.write(key);
            counterNonceStrm.write(iv);
            lenPayloadStrm.write(msg_len);
            // read msg and write to msg_stream
            for (ap_uint<64> i = 0; i < msg_len; i += 64) {
#pragma HLS pipeline II = 1
                ap_uint<128> msg_part1 = rawStrm.read();
                ap_uint<128> msg_part2 = rawStrm.read();
                ap_uint<128> msg_part3 = rawStrm.read();
                ap_uint<128> msg_part4 = rawStrm.read();
                ap_uint<512> msg_part = 0;
                msg_part.range(127, 0) = msg_part1;
                msg_part.range(255, 128) = msg_part2;
                msg_part.range(383, 256) = msg_part3;
                msg_part.range(511, 384) = msg_part4;
                plainStrm.write(msg_part);
                payloadStrm.write(msg_part1);
                payloadStrm.write(msg_part2);
                payloadStrm.write(msg_part3);
                payloadStrm.write(msg_part4);
                ePlainStrm.write(false);
            }
            ePlainStrm.write(true);
            endLenStrm.write(true);
            endLenStrm.write(false);
            }
        }

    void writeRaw(ap_uint<128>* ddr, hls::stream<ap_uint<128> >& rawStrm, hls::stream<ap_uint<16> >& numRawStrm) {
        ap_uint<64> addr = 0;
        ap_uint<16> numRaw = numRawStrm.read();
        while (numRaw != 0) {
            for (ap_uint<16> i = 0; i < numRaw; i++) {
#pragma HLS pipeline II = 1
                ddr[addr + i] = rawStrm.read();
            }
            addr += numRaw;
            numRaw = numRawStrm.read();
        }
    }

    // out packet format:
    // msg_len, ciphertext, tag
    void preparePack(ap_uint<64> msg_num,
                     hls::stream<ap_uint<512> >& cipherStrm,
                     hls::stream<bool>& eCipherStrm,
                     hls::stream<ap_uint<128> >& tagStrm,
                     hls::stream<ap_uint<128> >& rawStrm,
                     hls::stream<ap_uint<16> >& numRawStrm) {
        ap_uint<16> numRaw = 0;

        rawStrm.write(ap_uint<128>(msg_num));
        numRaw++;         

        for(ap_uint<64> i = 0; i < msg_num; i++){
            while(!eCipherStrm.read()){
                ap_uint<512> msg_part = cipherStrm.read();
                rawStrm.write(msg_part.range(127, 0));
                numRaw++;
                if (numRaw == 64) {
                    numRaw = 0;
                    numRawStrm.write(ap_uint<16>(64));
                }
                rawStrm.write(msg_part.range(255, 128));
                numRaw++;
                if (numRaw == 64) {
                    numRaw = 0;
                    numRawStrm.write(ap_uint<16>(64));
                }
                rawStrm.write(msg_part.range(383, 256));
                numRaw++;
                if (numRaw == 64) {
                    numRaw = 0;
                    numRawStrm.write(ap_uint<16>(64));
                }
                rawStrm.write(msg_part.range(511, 384));
                numRaw++;
                if (numRaw == 64) {
                    numRaw = 0;
                    numRawStrm.write(ap_uint<16>(64));
                }
            }
            rawStrm.write(tagStrm.read());
            numRaw++;
            if (numRaw == 64) {
                numRaw = 0;
                numRawStrm.write(ap_uint<16>(64));
            }
        }   
        
        if (numRaw != 0) {
            numRawStrm.write(numRaw);
        }
        numRawStrm.write(0);
    }

   public:
    ChaChaPack() {
#pragma HLS inline
    }

#ifndef __SYNTHESIS__
    /**
     * @brief Add one message.
     *
     * @msg Pointer of message to be added.
     * @len Length of message to be added.
     * @iv Initialization vector of this message.
     * @key Encryption key
     * @return return true if successfully add message, other wise false.
     */

    // message is serialized:
    // Format:
    // msg_len, aad_len, iv, key, aad (optional), msg
    bool addOneMsg(unsigned char* msg, int64_t len, unsigned char* iv, unsigned char* key) {
        if (!isReset) {
            std::cout << "Not reset yet, please call reset()" << std::endl;
            return false;
        }
        if (!isMemAlloced) {
            std::cout << "Memory not alloced yet, please call setPtr()" << std::endl;
            return false;
        }

        // row_inc: 1 for len, 1 for aad_len, 1 for iv, aad, msg, 1 or 2 for key
        int64_t row_inc = 1 + 1 + (len + 15) / 16;
        if (KeyW > 128) {
            row_inc += 2;
        } else {
            row_inc += 1;
        }

        if (curr_ptr + row_inc > total_row) {
            std::cout << "Memory left not enough to add one message" << std::endl;
            return false;
        }

        // set msg length
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        *(int64_t*)(buffer_ptr + (curr_ptr * 16)) = len;
        curr_ptr++;

        // set iv
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)iv, 16);
        curr_ptr++;

        // set key (2 rows for large keys)
        if (KeyW > 128) {
            memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 32);
        } else {
            memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, 16);
        }
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)key, KeyW / 8);
        if (KeyW > 128) {
            curr_ptr += 2;
        } else {
            curr_ptr += 1;
        }

        // set msg
        memset((void*)(buffer_ptr + (curr_ptr * 16)), 0, (len + 15) / 16 * 16);
        memcpy((void*)(buffer_ptr + (curr_ptr * 16)), (void*)msg, len);
        curr_ptr += (len + 15) / 16;

        msg_num++;
        return true;
    }
#endif

    void scanPack(ap_uint<128>* ddr,
                  ap_uint<64> msg_num,
                  ap_uint<64> row_num,
                  hls::stream<ap_uint<KeyW> >& cipherKeyStrm,
                  hls::stream<ap_uint<128> >& counterNonceStrm,
                  hls::stream<ap_uint<512> >& plainStrm,
                  hls::stream<bool>& ePlainStrm,
                  hls::stream<ap_uint<KeyW> >& macKeyStrm,
                  hls::stream<ap_uint<128> >& payloadStrm,
                  hls::stream<ap_uint<64> >& lenPayloadStrm,
                  hls::stream<bool>& endLenStrm) {
#pragma HLS dataflow
        hls::stream<ap_uint<128> > rawStrm;
#pragma HLS stream variable = rawStrm depth = 128
        scanRaw(ddr, row_num, rawStrm);
        parsePack(msg_num, rawStrm, cipherKeyStrm, counterNonceStrm, plainStrm, ePlainStrm, macKeyStrm, payloadStrm, lenPayloadStrm, endLenStrm);
    }

    void writeOutMsgPack(ap_uint<128>* ddr,
                         ap_uint<64> msg_num,
                         hls::stream<ap_uint<512> >& cipherStrm,
                         hls::stream<bool>& eCipherStrm,
                         hls::stream<ap_uint<128> >& tagStrm) {
#pragma HLS dataflow
        hls::stream<ap_uint<128> > rawStrm;
#pragma HLS stream variable = rawStrm depth = 128
        hls::stream<ap_uint<16> > numRawStrm;
#pragma HLS stream variable = numRawStrm depth = 4
        preparePack(msg_num, cipherStrm, eCipherStrm, tagStrm, rawStrm, numRawStrm);
        writeRaw(ddr, rawStrm, numRawStrm);
    }
};

} // namespace internal
} // namespace security
} // namespace xf
#endif
