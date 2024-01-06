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
#ifndef _DSPLIB_FIR_SR_SYM_REF_GRAPH_HPP_
#define _DSPLIB_FIR_SR_SYM_REF_GRAPH_HPP_

/*
This file holds the declaration of the reference model
graph class for the Single Rate Symmetrical FIR filter.
*/
#include <adf.h>
#include <vector>
#include "fir_sr_sym_ref.hpp"
#include "fir_ref_utils.hpp"
#include "widget_api_cast_ref.hpp"

namespace xf {
namespace dsp {
namespace aie {
namespace fir {
namespace sr_sym {
using namespace adf;
using namespace xf::dsp::aie::widget::api_cast;
class empty {};
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_CASC_LEN = 1,
          unsigned int TP_USE_COEFF_RELOAD = 0,
          unsigned int TP_NUM_OUTPUTS = 1,
          unsigned int TP_API = 0>
class fir_sr_sym_ref_graph : public graph {
   private:
    using coeff_port = typename std::conditional<(TP_USE_COEFF_RELOAD == 1), port<input>, empty>::type;
    using out2_port = typename std::conditional<(TP_NUM_OUTPUTS == 2), port<output>, empty>::type;
    using widget_kernel_out = typename std::conditional<(TP_NUM_OUTPUTS == 2), kernel, empty>::type;

   public:
    port<input> in;
    coeff_port coeff;
    port<output> out;
    out2_port out2;

    // FIR Kernel
    kernel m_firKernel;
    widget_kernel_out m_widgetKernelOut;
    const int kInterleavePattern = 1;

    // Constructor
    fir_sr_sym_ref_graph(const std::vector<TT_COEFF>& taps) {
        m_firKernel =
            kernel::create_object<fir_sr_sym_ref<TT_DATA, TT_COEFF, TP_FIR_LEN, TP_SHIFT, TP_RND, TP_INPUT_WINDOW_VSIZE,
                                                 TP_USE_COEFF_RELOAD, 0, TP_API> >(taps);
        create_connections();
    }

    fir_sr_sym_ref_graph() {
        m_firKernel = kernel::create_object<fir_sr_sym_ref<TT_DATA, TT_COEFF, TP_FIR_LEN, TP_SHIFT, TP_RND,
                                                           TP_INPUT_WINDOW_VSIZE, TP_USE_COEFF_RELOAD, 1, TP_API> >();
        create_connections();
    }

    void create_connections() {
        printf("========================\n");
        printf("== FIR SR SYM REF Graph\n");
        printf("========================\n");

        // Create FIR class

        // Make connections

        connect<window<TP_INPUT_WINDOW_VSIZE * sizeof(TT_DATA), fnFirMargin<TP_FIR_LEN, TT_DATA>() * sizeof(TT_DATA)> >(
            in, m_firKernel.in[0]);
        if
            constexpr(TP_USE_COEFF_RELOAD == 1) { connect<parameter>(coeff, async(m_firKernel.in[1])); }

        // Size of output window in Bytes, multiplied by const interpolate factor of 2
        if
            constexpr(TP_NUM_OUTPUTS == 2) {
                constexpr int kNumInputs = 1;               // single Fir kernel output
                constexpr int kNumOutputs = TP_NUM_OUTPUTS; //
                m_widgetKernelOut =
                    kernel::create_object<widget_api_cast_ref<TT_DATA, USE_WINDOW_API, TP_API, kNumInputs,
                                                              TP_INPUT_WINDOW_VSIZE, kNumOutputs, 0> >();
                connect<window<TP_INPUT_WINDOW_VSIZE * sizeof(TT_DATA)> >(m_firKernel.out[0], m_widgetKernelOut.in[0]);

                if
                    constexpr(TP_API == USE_WINDOW_API) {
                        connect<window<TP_INPUT_WINDOW_VSIZE * sizeof(TT_DATA)> >(m_widgetKernelOut.out[0], out);
                        connect<window<TP_INPUT_WINDOW_VSIZE * sizeof(TT_DATA)> >(m_widgetKernelOut.out[1], out2);
                    }
                else {
                    connect<stream>(m_widgetKernelOut.out[0], out);
                    connect<stream>(m_widgetKernelOut.out[1], out2);
                }

                source(m_widgetKernelOut) = "widget_api_cast_ref.cpp";
                runtime<ratio>(m_widgetKernelOut) = 0.9;
            }
        else {
            connect<window<TP_INPUT_WINDOW_VSIZE * sizeof(TT_DATA)> >(m_firKernel.out[0], out);
        }
        // Specify mapping constraints
        runtime<ratio>(m_firKernel) = 0.4;

        // Source files
        source(m_firKernel) = "fir_sr_sym_ref.cpp";
    };
};
}
}
}
}
}
#endif // _DSPLIB_FIR_SR_SYM_REF_GRAPH_HPP_
