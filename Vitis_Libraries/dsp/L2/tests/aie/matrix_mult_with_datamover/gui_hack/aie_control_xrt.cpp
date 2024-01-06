/*
 * Copyright 2022 Xilinx, Inc.
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
#include <iostream>
#include "adf/adf_api/AIEControlConfig.h"
#include "../../../../../L1/include/aie/matrix_mult.hpp"

/************************** Graph Configurations  *****************************/

adf::GraphConfig GraphConfigurations[] = {
    //{id, name, graphLoadElfFunc, graphInitFunc, graphDebugHalt, coreColumns, coreRows, iterMemColumns, iterMemRows,
    // iterMemAddrs, triggered, plKernelInstanceNames, plAxiLiteModes, plDriverStartFuncs, plDriverCheckIPDoneFuncs}
    {
        0,
        "matMult",
        nullptr,
        nullptr,
        nullptr,
        {24, 24, 25},
        {0, 1, 0},
        {24, 25, 25},
        {0, 1, 1},
        {0x74e4, 0x4, 0x2004},
        {0, 0, 0},
        {},
        {},
        {},
        {},
    },
};
const int NUM_GRAPH = 1;

/************************** PLIO Configurations  *****************************/

adf::PLIOConfig PLIOConfigurations[] = {
    //{id, name, loginal_name, shim_column, slaveOrMaster, streamId}
    {0, "in1", "DataIn1", 24, 0, 1},
    {1, "in2", "DataIn2", 24, 0, 4},
    {2, "out1", "DataOut1", 25, 1, 0},
};
const int NUM_PLIO = 3;

/************************** ADF API initializer *****************************/

class InitializeAIEControlXRT {
   public:
    InitializeAIEControlXRT() {
        std::cout << "Initializing ADF API..." << std::endl;
#ifdef __EXCLUDE_PL_CONTROL__
        bool exclude_pl_control = true;
#else
        bool exclude_pl_control = false;
#endif
        adf::initializeConfigurations(nullptr, 0, 0, 0, GraphConfigurations, NUM_GRAPH, nullptr, 0, nullptr, 0, nullptr,
                                      0, nullptr, 0, nullptr, 0, nullptr, 0, PLIOConfigurations, NUM_PLIO, nullptr, 0,
                                      0, nullptr, false, exclude_pl_control, false, nullptr, true, 2);
    }
} initAIEControlXRT;

#if !defined(__CDO__)

// Kernel Stub Definition
template <>
void xf::dsp::aie::blas::matrix_mult::
    matrix_mult<cint16, cint16, 16, 16, 16, 20, 0, 0, 1, 0, 256, 256, false, false, 16, 16, 16, 0, 1>::matMult(
        input_window<cint16>*, input_window<cint16>*, output_window<cint16>*) { /* Stub */
}
template <>
void xf::dsp::aie::blas::matrix_mult::tilerKernelClass<4, 2, 16, 16, 1, cint16>::tile(
    input_window<cint16>*, output_window<cint16>*) { /* Stub */
}
template <>
void xf::dsp::aie::blas::matrix_mult::tilerKernelClass<4, 4, 16, 16, 0, cint16>::tile(
    input_window<cint16>*, output_window<cint16>*) { /* Stub */
}
template <>
void xf::dsp::aie::blas::matrix_mult::untilerKernelClass<4, 2, 16, 16, 0, cint16>::unTile(
    input_window<cint16>*, output_window<cint16>*) { /* Stub */
}
#endif
