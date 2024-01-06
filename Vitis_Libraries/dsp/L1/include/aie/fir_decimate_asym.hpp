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
#ifndef _DSPLIB_FIR_DECIMATE_ASYM_HPP_
#define _DSPLIB_FIR_DECIMATE_ASYM_HPP_

/*
Decimator Asymmetric FIR

This file exists to capture the definition of the single rate asymmetric FIR
filter kernel class.
The class definition holds defensive checks on parameter range and other
legality.
The constructor definition is held in this class because this class must be
accessible to graph level aie compilation.
The main runtime filter function is captured elsewhere as it contains aie
intrinsics which are not included in aie graph level
compilation.
*/

/* Coding conventions
   TT_      template type suffix
   TP_      template parameter suffix
*/

/* Design Notes
   Note that the AIE intrinsics operate on increasing indices, but in a conventional FIR there is a convolution of data
   and coefficients.
   So as to achieve the impulse response from the filter which matches the coefficient set, the coefficient array has to
   be reversed
   to compensate for the action of the intrinsics. This reversal is performed in the constructor. To avoid common-mode
   errors
   the reference model performs this reversal at run-time. This decimator implementation solves all polyphases for an
   output in a single lane.
   For large decimation factors, or large number of lanes (as required by data and coefficient type), it is not always
   possible to accommodate the
   input data step between lanes required because the maximum offset between lanes in a single operation is limited to
   15.
   Hence, the implementation may operate on fewer lanes per operation than the hardware supports.
*/

#include <array>

#include <adf.h>
#include "fir_utils.hpp"
#include "fir_decimate_asym_traits.hpp"

#include <vector>

namespace xf {
namespace dsp {
namespace aie {
namespace fir {
namespace decimate_asym {

//-----------------------------------------------------------------------------------------------------
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          bool TP_CASC_IN = CASC_IN_FALSE,
          bool TP_CASC_OUT = CASC_OUT_FALSE,
          unsigned int TP_FIR_RANGE_LEN = TP_FIR_LEN,
          unsigned int TP_KERNEL_POSITION = 0,
          unsigned int TP_CASC_LEN = 1,
          unsigned int TP_USE_COEFF_RELOAD = 0,
          unsigned int TP_NUM_OUTPUTS = 1,
          unsigned int TP_DUAL_IP = 0,
          unsigned int TP_API = 0>
class kernelFilterClass {
   private:
    // Parameter value defensive and legality checks
    // static_assert(TP_FIR_RANGE_LEN >= FIR_LEN_MIN,"ERROR: Illegal combination of design FIR length and cascade
    // length, resulting in kernel FIR length below minimum required value. ");
    static_assert(TP_FIR_LEN % TP_DECIMATE_FACTOR == 0, "ERROR: TP_FIR_LEN must be a multiple of TP_DECIMATE_FACTOR");
    static_assert(TP_FIR_RANGE_LEN % TP_DECIMATE_FACTOR == 0,
                  "ERROR: Illegal combination of design FIR length and cascade length. TP_FIR_RANGE_LEN must be a "
                  "multiple of TP_DECIMATE_FACTOR");
    static_assert(TP_DECIMATE_FACTOR >= DECIMATE_FACTOR_MIN && TP_DECIMATE_FACTOR <= DECIMATE_FACTOR_MAX,
                  "ERROR:TP_DECIMATE_FACTOR is outside the supported range.");
    static_assert(TP_SHIFT >= SHIFT_MIN && TP_SHIFT <= SHIFT_MAX, "ERROR: TP_SHIFT is out of the supported range.");
    static_assert(TP_RND >= ROUND_MIN && TP_RND <= ROUND_MAX, "ERROR: TP_RND is out of the supported range.");
    static_assert(fnEnumType<TT_DATA>() != enumUnknownType, "ERROR: TT_DATA is not a supported type.");
    static_assert(fnEnumType<TT_COEFF>() != enumUnknownType, "ERROR: TT_COEFF is not a supported type.");
    static_assert(fnFirDecAsymTypeSupport<TT_DATA, TT_COEFF>() != 0,
                  "ERROR: The combination of TT_DATA and TT_COEFF is not supported for this class.");
    static_assert(fnTypeCheckDataCoeffSize<TT_DATA, TT_COEFF>() != 0,
                  "ERROR: TT_DATA type less precise than TT_COEFF is not supported.");
    static_assert(fnTypeCheckDataCoeffCmplx<TT_DATA, TT_COEFF>() != 0,
                  "ERROR: real TT_DATA with complex TT_COEFF is not supported.");
    static_assert(fnTypeCheckDataCoeffFltInt<TT_DATA, TT_COEFF>() != 0,
                  "ERROR: a mix of float and integer types of TT_DATA and TT_COEFF is not supported.");
    static_assert(TP_NUM_OUTPUTS > 0 && TP_NUM_OUTPUTS <= 2, "ERROR: only single or dual outputs are supported.");
    static_assert(!(std::is_same<TT_DATA, cfloat>::value || std::is_same<TT_DATA, float>::value) || (TP_SHIFT == 0),
                  "ERROR: TP_SHIFT cannot be performed for TT_DATA=cfloat, so must be set to 0");

    // constants derived from configuration parameters
    static constexpr unsigned int m_kDataRegVsize = kBuffSize128Byte / (sizeof(TT_DATA)); // buff size in Bytes
    static constexpr unsigned int m_kColumns =
        fnNumColumnsDecAsym<TT_DATA, TT_COEFF>(); // number of mult-adds per lane for main intrinsic
    static constexpr unsigned int m_kLanes = fnNumLanesDecAsym<TT_DATA, TT_COEFF>(); // number of operations in parallel
                                                                                     // of this type combinations that
                                                                                     // the vector processor can do.
    static constexpr unsigned int m_kInitLoadsInReg =
        fnDataLoadsInRegDecAsym<TT_DATA>(); // 4;  //ratio of sbuff to init load size.
    static constexpr unsigned int m_kInitLoadVsize =
        fnDataLoadVsizeDecAsym<TT_DATA>(); // number of samples in 256-bit init upd_w loads
    static constexpr unsigned int m_kDataLoadSize = fnLoadSizeDecAsym<TT_DATA, TT_COEFF>(); // 256-bit or 128-bit loads
    static constexpr unsigned int m_kDataLoadVsize =
        m_kDataLoadSize /
        (8 * sizeof(TT_DATA)); // 8 samples when 256-bit loads are in use, 4 samples when 128-bit loads are used.
    static constexpr unsigned int m_kDataLoadsInReg =
        m_kDataLoadSize == 256 ? 4 : 8; // kBuffSize128Byte / m_kDataLoadVsize
    static constexpr unsigned int m_kSamplesInBuff = m_kDataLoadsInReg * m_kDataLoadVsize;
    static constexpr unsigned int m_kWinAccessByteSize =
        fnWinAccessByteSize<TT_DATA, TT_COEFF>(); // The memory data path is min 128-bits wide for vector operations
    static constexpr unsigned int m_kFirRangeOffset =
        fnFirRangeOffset<TP_FIR_LEN, TP_CASC_LEN, TP_KERNEL_POSITION, TP_DECIMATE_FACTOR>(); // FIR Cascade Offset for
                                                                                             // this kernel position
    static constexpr unsigned int m_kFirMargin = fnFirMargin<TP_FIR_LEN, TT_DATA>();         // FIR Margin.
    static constexpr unsigned int m_kFirMarginOffset =
        fnFirMargin<TP_FIR_LEN, TT_DATA>() - TP_FIR_LEN + 1; // FIR Margin Offset.
    static constexpr unsigned int m_kFirInitOffset = m_kFirRangeOffset + m_kFirMarginOffset;
    static constexpr unsigned int m_kDataBuffXOffset =
        m_kFirInitOffset % (m_kWinAccessByteSize / sizeof(TT_DATA)); // Remainder of m_kFirInitOffset divided by 128bit
    static constexpr unsigned int m_kInitDataNeeded = TP_FIR_RANGE_LEN + (m_kLanes - 1) * TP_DECIMATE_FACTOR;
    static constexpr unsigned int m_kXoffsetRange = fnMaxXoffsetRange<TT_DATA>();
    static constexpr eArchType m_kArchIncrStrobeEn =
        (fnFirDecIncStrSupported<TT_DATA, TT_COEFF>() == SUPPORTED) ? kArchIncrStrobe : kArchBasic;
    static constexpr eArchType m_kArchWindow =
        ((TP_INPUT_WINDOW_VSIZE / TP_DECIMATE_FACTOR) % (m_kLanes * m_kInitLoadsInReg) == 0) &&
                (m_kInitDataNeeded <= m_kInitLoadVsize * (m_kInitLoadsInReg - 1) + 1)
            ? m_kArchIncrStrobeEn
            : kArchBasic;
    static constexpr eArchType m_kArch = TP_API == 1 ? kArchStream : m_kArchWindow;
    static constexpr unsigned int m_kDFDataRange = m_kDataBuffXOffset + (m_kLanes - 1) * TP_DECIMATE_FACTOR;
    static constexpr unsigned int m_kDFX = (m_kLanes - 1) * TP_DECIMATE_FACTOR < m_kXoffsetRange ? kLowDF : kHighDF;
    static constexpr unsigned int m_kFirLenCeilCols = CEIL(TP_FIR_RANGE_LEN, m_kColumns);
    static constexpr unsigned int m_kZbuffSize = 32; // kZbuffSize (256bit) - const for all data/coeff types
    static constexpr unsigned int m_kCoeffRegVsize = m_kZbuffSize / sizeof(TT_COEFF);
    static constexpr unsigned int m_kVOutSize = fnVOutSizeDecAsym<TT_DATA, TT_COEFF>();
    static constexpr unsigned int m_kLsize =
        (TP_INPUT_WINDOW_VSIZE / TP_DECIMATE_FACTOR) /
        m_kVOutSize; // loop length, given that <m_kVOutSize> samples are output per iteration of loop
    unsigned int m_kDecimateOffsets, m_kDecimateOffsetsHi; // hi is for int16/int16 only.

    static constexpr unsigned int m_kStreamReadWidth =
        (TP_DECIMATE_FACTOR % 2 == 0) ? 256 : fnStreamReadWidth<TT_DATA, TT_COEFF>();
    static constexpr unsigned int m_kStreamLoadVsize = m_kStreamReadWidth / 8 / sizeof(TT_DATA); //
    static constexpr int streamRptFactor = 8;                                                    //
    static constexpr int marginLoadsMappedToBuff = (m_kFirMargin % m_kSamplesInBuff) / m_kStreamLoadVsize;
    static constexpr int streamDataOffsetWithinBuff = (m_kFirInitOffset) % m_kSamplesInBuff;
    static constexpr int emptyInitLanes =
        CEIL((TP_FIR_LEN - TP_FIR_RANGE_LEN - m_kFirRangeOffset), TP_DECIMATE_FACTOR) / TP_DECIMATE_FACTOR;
    static constexpr int streamInitNullAccs =
        (emptyInitLanes / m_kVOutSize); // Number of Null Mac Vectors sent as partial prouducts over cascade.

    static constexpr int streamInitAccs = (CEIL(streamInitNullAccs, streamRptFactor) - streamInitNullAccs);

    alignas(32) int delay[32] = {0};
    int doInit = (TP_CASC_LEN == 1 || streamInitNullAccs == 0) ? 0 : 1;

    // Coefficient Load Size - number of samples in 256-bits
    static constexpr unsigned int m_kCoeffLoadSize = 256 / 8 / sizeof(TT_COEFF);
    alignas(32) TT_COEFF
        m_oldInTaps[CEIL(TP_FIR_LEN, m_kCoeffLoadSize)]; // Previous user input coefficients with zero padding
    bool m_coeffnEq;                                     // Are coefficients sets equal?

    static_assert(TP_INPUT_WINDOW_VSIZE % (TP_DECIMATE_FACTOR * m_kLanes) == 0,
                  "ERROR: TP_INPUT_WINDOW_VSIZE must be a multiple of TP_DECIMATE_FACTOR  and of the number of lanes "
                  "for the MUL/MAC intrinsic");
    static_assert(m_kDataRegVsize - m_kDataLoadVsize >= m_kDFDataRange,
                  "ERROR: TP_DECIMATION_FACTOR exceeded for this data/coeff type combination. Required input data "
                  "exceeds input vector's register offset address range.");
    static_assert(!(m_kArch == kArchStream && m_kDFX == kHighDF),
                  "ERROR: TP_DECIMATION_FACTOR exceeded for this data/coeff type combination. Required input data "
                  "exceeds input vector's register offset address range.");
    static_assert(!(m_kArch == kArchStream && m_kInitDataNeeded >= m_kSamplesInBuff),
                  "ERROR: TP_FIR_RANGE_LEN exceeds max supported range for this data/coeff type combination. Increase "
                  "TP_CASC_LEN to split the workload over more kernels.");
    static_assert(!(m_kArch == kArchStream &&
                    TP_INPUT_WINDOW_VSIZE % (TP_DECIMATE_FACTOR * m_kLanes * streamRptFactor) != 0),
                  "ERROR: TP_INPUT_WINDOW_VSIZE must be a multiple of (TP_DECIMATE_FACTOR * 8)  and of the number of "
                  "lanes for the streaming MUL/MAC intrinsic");
    // The coefficients array must include zero padding up to a multiple of the number of columns
    // the MAC intrinsic used to eliminate the accidental inclusion of terms beyond the FIR length.
    // Since this zero padding cannot be applied to the class-external coefficient array
    // the supplied taps are copied to an internal array, m_internalTaps, which can be padded.
    alignas(32) TT_COEFF m_internalTaps[CEIL(TP_FIR_RANGE_LEN, m_kCoeffLoadSize)]; // Filter taps/coefficients

    // Filter implementation functions
    void filterSelectArch(T_inputIF<TP_CASC_IN, TT_DATA, TP_DUAL_IP> inInterface,
                          T_outputIF<TP_CASC_OUT, TT_DATA> outInterface);
    void filterBasic(T_inputIF<TP_CASC_IN, TT_DATA, TP_DUAL_IP> inInterface,
                     T_outputIF<TP_CASC_OUT, TT_DATA> outInterface);
    void filterIncrStrobe(T_inputIF<TP_CASC_IN, TT_DATA, TP_DUAL_IP> inInterface,
                          T_outputIF<TP_CASC_OUT, TT_DATA> outInterface);
    void filterStream(T_inputIF<TP_CASC_IN, TT_DATA, TP_DUAL_IP> inInterface,
                      T_outputIF<TP_CASC_OUT, TT_DATA> outInterface);

   public:
    // Access function for AIE Synthesizer
    static unsigned int get_m_kArch() { return m_kArch; };

    // Constructor for reloadable coefficient designs
    // Calculates offsets required for coefficient reloads and m_kDecimateOffsets
    kernelFilterClass() : m_oldInTaps{}, m_internalTaps{} { setDecimateOffsets(); }

    // Constructor for static coefficient designs
    // Calculates m_kDecimateOffsets and writes coefficients to m_internalTaps
    kernelFilterClass(const TT_COEFF (&taps)[TP_FIR_LEN]) : m_internalTaps{} {
        setDecimateOffsets();
        // Loads taps/coefficients
        firReload(taps);
    }

    // setDecimateOffsets
    void setDecimateOffsets() {
        switch (TP_DECIMATE_FACTOR) {
            case 2:
                m_kDecimateOffsets = 0xECA86420;
                break; // No point in hi because range is exceeded.
            case 3:
                m_kDecimateOffsets = m_kDFX == kLowDF ? 0x9630 : m_kColumns == 2 ? 0xA9764310 : 0x3030;
                break; // only good up to 4 lanes.
            case 4:
                m_kDecimateOffsets = 0xC840;
                break; // only good up to 4 lanes //
            case 5:
                m_kDecimateOffsets = 0xFA50;
                break; // only good up to 4 lanes
            case 6:
                m_kDecimateOffsets = m_kColumns == 2 ? 0x76107610 : 0x98763210;
                break; // only uses highDF architecture with select intrinsic. Different pattern, depending on
                       // intrinsic's columns requirement.
            case 7:
                m_kDecimateOffsets = m_kColumns == 2 ? 0x87108710 : 0xA9873210;
                break; // only uses highDF architecture with select intrinsic. Different pattern, depending on
                       // intrinsic's columns requirement.
            default:
                break;
        }
    }; // setDecimateOffsets

    // Copys taps into m_internalTaps

    void firReload(const TT_COEFF* taps) {
        TT_COEFF* tapsPtr = (TT_COEFF*)taps;
        firReload(tapsPtr);
    }

    void firReload(TT_COEFF* taps) {
        // Loads taps/coefficients
        for (int i = 0; i < TP_FIR_RANGE_LEN; i++) {
            m_internalTaps[i] =
                taps[TP_FIR_LEN - 1 - i -
                     fnFirRangeOffset<TP_FIR_LEN, TP_CASC_LEN, TP_KERNEL_POSITION, TP_DECIMATE_FACTOR>()];
        }
    }

    // Filter kernel for static coefficient designs
    void filterKernel(T_inputIF<TP_CASC_IN, TT_DATA, TP_DUAL_IP> inInterface,
                      T_outputIF<TP_CASC_OUT, TT_DATA> outInterface);

    // Filter kernel for reloadable coefficient designs
    void filterKernel(T_inputIF<TP_CASC_IN, TT_DATA, TP_DUAL_IP> inInterface,
                      T_outputIF<TP_CASC_OUT, TT_DATA> outInterface,
                      const TT_COEFF (&inTaps)[TP_FIR_LEN]);

    void filterKernelRtp(T_inputIF<TP_CASC_IN, TT_DATA, TP_DUAL_IP> inInterface,
                         T_outputIF<TP_CASC_OUT, TT_DATA> outInterface);
};

//-----------------------------------------------------------------------------------------------------
// Single kernel base specialization. No cascade ports. Static coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          bool TP_CASC_IN = CASC_IN_FALSE,
          bool TP_CASC_OUT = CASC_OUT_FALSE,
          unsigned int TP_FIR_RANGE_LEN = TP_FIR_LEN,
          unsigned int TP_KERNEL_POSITION = 0,
          unsigned int TP_CASC_LEN = 1,
          unsigned int TP_USE_COEFF_RELOAD = 0, // 1 = use coeff reload, 0 = don't use coeff reload
          unsigned int TP_NUM_OUTPUTS = 1,
          unsigned int TP_DUAL_IP = 0,
          unsigned int TP_API = 0>
class fir_decimate_asym : public kernelFilterClass<TT_DATA,
                                                   TT_COEFF,
                                                   TP_FIR_LEN,
                                                   TP_DECIMATE_FACTOR,
                                                   TP_SHIFT,
                                                   TP_RND,
                                                   TP_INPUT_WINDOW_VSIZE,
                                                   TP_CASC_IN,
                                                   TP_CASC_OUT,
                                                   TP_FIR_RANGE_LEN,
                                                   TP_KERNEL_POSITION,
                                                   TP_CASC_LEN,
                                                   TP_USE_COEFF_RELOAD,
                                                   TP_NUM_OUTPUTS,
                                                   TP_DUAL_IP,
                                                   TP_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            TP_CASC_IN,
                            TP_CASC_OUT,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            TP_USE_COEFF_RELOAD,
                            TP_NUM_OUTPUTS,
                            TP_DUAL_IP,
                            TP_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* inWindow, output_window<TT_DATA>* outWindow);
};

// Single kernel specialization. No cascade ports. Static coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        false,
                        false,
                        TP_FIR_RANGE_LEN,
                        0,
                        1,
                        0,
                        2,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   false,
                                                                   false,
                                                                   TP_FIR_RANGE_LEN,
                                                                   0,
                                                                   1,
                                                                   0,
                                                                   2,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            false,
                            false,
                            TP_FIR_RANGE_LEN,
                            0,
                            1,
                            0,
                            2,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* inWindow, output_window<TT_DATA>* outWindow, output_window<TT_DATA>* outWindow2);
};

//-----------------------------------------------------------------------------------------------------
// Single kernel specialization. No cascade ports. Using coefficient reload, single output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* __restrict inWindow,
                output_window<TT_DATA>* __restrict outWindow,
                const TT_COEFF (&inTaps)[TP_FIR_LEN]);
};

// Single kernel specialization. No cascade ports. Using coefficient reload, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        2,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   2,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* __restrict inWindow,
                output_window<TT_DATA>* __restrict outWindow,
                output_window<TT_DATA>* __restrict outWindow2,
                const TT_COEFF (&inTaps)[TP_FIR_LEN]);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - final kernel. Static coefficients single output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* inWindow, input_stream_cacc48* inCascade, output_window<TT_DATA>* outWindow);
};

// Partially specialized classes for cascaded interface - final kernel. Static coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        2,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   2,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            2,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* inWindow,
                input_stream_cacc48* inCascade,
                output_window<TT_DATA>* outWindow,
                output_window<TT_DATA>* outWindow2);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - first kernel. Static coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* inWindow,
                output_stream_cacc48* outCascade,
                output_window<TT_DATA>* broadcastWindow);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - middle kernel. Static coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* inWindow,
                input_stream_cacc48* inCascade,
                output_stream_cacc48* outCascade,
                output_window<TT_DATA>* broadcastWindow);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - final kernel. Reloadable coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* inWindow, input_stream_cacc48* inCascade, output_window<TT_DATA>* outWindow);
};

// Partially specialized classes for cascaded interface - final kernel. Reloadable coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        2,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   2,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* inWindow,
                input_stream_cacc48* inCascade,
                output_window<TT_DATA>* outWindow,
                output_window<TT_DATA>* outWindow2);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - first kernel. Reloadable coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* inWindow,
                output_stream_cacc48* outCascade,
                output_window<TT_DATA>* broadcastWindow,
                const TT_COEFF (&inTaps)[TP_FIR_LEN]);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - middle kernel. Reeloadable coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_WINDOW_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_WINDOW_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_WINDOW_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_window<TT_DATA>* inWindow,
                input_stream_cacc48* inCascade,
                output_stream_cacc48* outCascade,
                output_window<TT_DATA>* broadcastWindow);
};

// ----------------------------------------------------------------------------
// ---------------------------------- STREAM ----------------------------------
// ----------------------------------------------------------------------------

//-----------------------------------------------------------------------------------------------------
// Single kernel base specialization. No cascade ports. Static coefficients

// Single kernel specialization. No cascade ports. Static coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        false,
                        false,
                        TP_FIR_RANGE_LEN,
                        0,
                        1,
                        0,
                        1,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   false,
                                                                   false,
                                                                   TP_FIR_RANGE_LEN,
                                                                   0,
                                                                   1,
                                                                   0,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            false,
                            false,
                            TP_FIR_RANGE_LEN,
                            0,
                            1,
                            0,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream, output_stream<TT_DATA>* outStream);
};
// Single kernel specialization. No cascade ports. Static coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        false,
                        false,
                        TP_FIR_RANGE_LEN,
                        0,
                        1,
                        0,
                        2,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   false,
                                                                   false,
                                                                   TP_FIR_RANGE_LEN,
                                                                   0,
                                                                   1,
                                                                   0,
                                                                   2,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            false,
                            false,
                            TP_FIR_RANGE_LEN,
                            0,
                            1,
                            0,
                            2,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream, output_stream<TT_DATA>* outStream, output_stream<TT_DATA>* outStream2);
};

//-----------------------------------------------------------------------------------------------------
// Single kernel specialization. No cascade ports. Using coefficient reload, single output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                output_stream<TT_DATA>* outStream,
                const TT_COEFF (&inTaps)[TP_FIR_LEN]);
};

// Single kernel specialization. No cascade ports. Using coefficient reload, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        2,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   2,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                output_stream<TT_DATA>* outStream,
                output_stream<TT_DATA>* outStream2,
                const TT_COEFF (&inTaps)[TP_FIR_LEN]);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - final kernel. Static coefficients single output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream, input_stream_cacc48* inCascade, output_stream<TT_DATA>* outStream);
};

// Partially specialized classes for cascaded interface - final kernel. Static coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        2,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   2,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            2,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream_cacc48* inCascade,
                output_stream<TT_DATA>* outStream,
                output_stream<TT_DATA>* outStream2);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - first kernel. Static coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream, output_stream_cacc48* outCascade);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - middle kernel. Static coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream, input_stream_cacc48* inCascade, output_stream_cacc48* outCascade);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - final kernel. Reloadable coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream, input_stream_cacc48* inCascade, output_stream<TT_DATA>* outStream);
};

// Partially specialized classes for cascaded interface - final kernel. Reloadable coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        2,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   2,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream_cacc48* inCascade,
                output_stream<TT_DATA>* outStream,
                output_stream<TT_DATA>* outStream2);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - first kernel. Reloadable coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                output_stream_cacc48* outCascade,
                const TT_COEFF (&inTaps)[TP_FIR_LEN]);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - middle kernel. Reeloadable coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_SINGLE,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_SINGLE,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_SINGLE,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream, input_stream_cacc48* inCascade, output_stream_cacc48* outCascade);
};

// ----------------------------------------------------------------------------
// ----------------------------- DUAL STREAM ----------------------------------
// ----------------------------------------------------------------------------

//-----------------------------------------------------------------------------------------------------
// Single kernel base specialization. No cascade ports. Static coefficients

// Single kernel specialization. No cascade ports. Static coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        false,
                        false,
                        TP_FIR_RANGE_LEN,
                        0,
                        1,
                        0,
                        1,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   false,
                                                                   false,
                                                                   TP_FIR_RANGE_LEN,
                                                                   0,
                                                                   1,
                                                                   0,
                                                                   1,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            false,
                            false,
                            TP_FIR_RANGE_LEN,
                            0,
                            1,
                            0,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream, input_stream<TT_DATA>* inStream2, output_stream<TT_DATA>* outStream);
};
// Single kernel specialization. No cascade ports. Static coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        false,
                        false,
                        TP_FIR_RANGE_LEN,
                        0,
                        1,
                        0,
                        2,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   false,
                                                                   false,
                                                                   TP_FIR_RANGE_LEN,
                                                                   0,
                                                                   1,
                                                                   0,
                                                                   2,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            false,
                            false,
                            TP_FIR_RANGE_LEN,
                            0,
                            1,
                            0,
                            2,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream<TT_DATA>* inStream2,
                output_stream<TT_DATA>* outStream,
                output_stream<TT_DATA>* outStream2);
};

//-----------------------------------------------------------------------------------------------------
// Single kernel specialization. No cascade ports. Using coefficient reload, single output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream<TT_DATA>* inStream2,
                output_stream<TT_DATA>* outStream,
                const TT_COEFF (&inTaps)[TP_FIR_LEN]);
};

// Single kernel specialization. No cascade ports. Using coefficient reload, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        2,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   2,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream<TT_DATA>* inStream2,
                output_stream<TT_DATA>* outStream,
                output_stream<TT_DATA>* outStream2,
                const TT_COEFF (&inTaps)[TP_FIR_LEN]);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - final kernel. Static coefficients single output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        1,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   1,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream<TT_DATA>* inStream2,
                input_stream_cacc48* inCascade,
                output_stream<TT_DATA>* outStream);
};

// Partially specialized classes for cascaded interface - final kernel. Static coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        2,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   2,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            2,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream<TT_DATA>* inStream2,
                input_stream_cacc48* inCascade,
                output_stream<TT_DATA>* outStream,
                output_stream<TT_DATA>* outStream2);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - first kernel. Static coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        1,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   1,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream, input_stream<TT_DATA>* inStream2, output_stream_cacc48* outCascade);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - middle kernel. Static coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_FALSE,
                        1,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_FALSE,
                                                                   1,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_FALSE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream<TT_DATA>* inStream2,
                input_stream_cacc48* inCascade,
                output_stream_cacc48* outCascade);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - final kernel. Reloadable coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream<TT_DATA>* inStream2,
                input_stream_cacc48* inCascade,
                output_stream<TT_DATA>* outStream);
};

// Partially specialized classes for cascaded interface - final kernel. Reloadable coefficients, dual output
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_FALSE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        2,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_FALSE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   2,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_FALSE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            2,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream<TT_DATA>* inStream2,
                input_stream_cacc48* inCascade,
                output_stream<TT_DATA>* outStream,
                output_stream<TT_DATA>* outStream2);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - first kernel. Reloadable coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_FALSE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_FALSE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_FALSE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream<TT_DATA>* inStream2,
                output_stream_cacc48* outCascade,
                const TT_COEFF (&inTaps)[TP_FIR_LEN]);
};

//-----------------------------------------------------------------------------------------------------
// Partially specialized classes for cascaded interface - middle kernel. Reeloadable coefficients
template <typename TT_DATA,
          typename TT_COEFF,
          unsigned int TP_FIR_LEN,
          unsigned int TP_DECIMATE_FACTOR,
          unsigned int TP_SHIFT,
          unsigned int TP_RND,
          unsigned int TP_INPUT_WINDOW_VSIZE,
          unsigned int TP_FIR_RANGE_LEN,
          unsigned int TP_KERNEL_POSITION,
          unsigned int TP_CASC_LEN>

class fir_decimate_asym<TT_DATA,
                        TT_COEFF,
                        TP_FIR_LEN,
                        TP_DECIMATE_FACTOR,
                        TP_SHIFT,
                        TP_RND,
                        TP_INPUT_WINDOW_VSIZE,
                        CASC_IN_TRUE,
                        CASC_OUT_TRUE,
                        TP_FIR_RANGE_LEN,
                        TP_KERNEL_POSITION,
                        TP_CASC_LEN,
                        USE_COEFF_RELOAD_TRUE,
                        1,
                        DUAL_IP_DUAL,
                        USE_STREAM_API> : public kernelFilterClass<TT_DATA,
                                                                   TT_COEFF,
                                                                   TP_FIR_LEN,
                                                                   TP_DECIMATE_FACTOR,
                                                                   TP_SHIFT,
                                                                   TP_RND,
                                                                   TP_INPUT_WINDOW_VSIZE,
                                                                   CASC_IN_TRUE,
                                                                   CASC_OUT_TRUE,
                                                                   TP_FIR_RANGE_LEN,
                                                                   TP_KERNEL_POSITION,
                                                                   TP_CASC_LEN,
                                                                   USE_COEFF_RELOAD_TRUE,
                                                                   1,
                                                                   DUAL_IP_DUAL,
                                                                   USE_STREAM_API> {
   public:
    // Constructor
    fir_decimate_asym()
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>() {}
    fir_decimate_asym(const TT_COEFF (&taps)[TP_FIR_LEN])
        : kernelFilterClass<TT_DATA,
                            TT_COEFF,
                            TP_FIR_LEN,
                            TP_DECIMATE_FACTOR,
                            TP_SHIFT,
                            TP_RND,
                            TP_INPUT_WINDOW_VSIZE,
                            CASC_IN_TRUE,
                            CASC_OUT_TRUE,
                            TP_FIR_RANGE_LEN,
                            TP_KERNEL_POSITION,
                            TP_CASC_LEN,
                            USE_COEFF_RELOAD_TRUE,
                            1,
                            DUAL_IP_DUAL,
                            USE_STREAM_API>(taps) {}

    // Register Kernel Class
    static void registerKernelClass() { REGISTER_FUNCTION(fir_decimate_asym::filter); }

    // FIR
    void filter(input_stream<TT_DATA>* inStream,
                input_stream<TT_DATA>* inStream2,
                input_stream_cacc48* inCascade,
                output_stream_cacc48* outCascade);
};
}
}
}
}
} // namespaces
#endif // _DSPLIB_FIR_DECIMATE_ASYM_HPP_
