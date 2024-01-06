/*
 * Copyright 2021 Xilinx, Inc.
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

#define XF_NPPC XF_NPPC1 // XF_NPPC1 --1PIXEL , XF_NPPC2--2PIXEL ,XF_NPPC4--4 and XF_NPPC8--8PIXEL

#define XF_WIDTH 3840  // MAX_COLS
#define XF_HEIGHT 2160 // MAX_ROWS

#define XF_BAYER_PATTERN XF_BAYER_GR // bayer pattern

#define T_8U 0
#define T_10U 0
#define T_12U 0
#define T_16U 1

#define XF_CCM_TYPE XF_CCM_bt2020_bt709

#if (T_16U || T_10U || T_12U)
#define CVTYPE unsigned short
#define CV_INTYPE CV_16UC1
#define CV_OUTTYPE CV_8UC3
#else
#define CVTYPE unsigned char
#define CV_INTYPE CV_8UC1
#define CV_OUTTYPE CV_8UC3
#endif

#if T_8U
#define XF_SRC_T XF_8UC1 // XF_8UC1
#define XF_LTM_T XF_8UC3 // XF_8UC3
#define XF_DST_T XF_8UC3 // XF_8UC3
#define XF_YUV_T XF_16UC1
#elif T_16U
#define XF_SRC_T XF_16UC1 // XF_8UC1
#define XF_LTM_T XF_8UC3  // XF_8UC3
#define XF_DST_T XF_16UC3 // XF_8UC3
#define XF_YUV_T XF_16UC1
#elif T_10U
#define XF_SRC_T XF_10UC1 // XF_8UC1
#define XF_LTM_T XF_8UC3  // XF_8UC3
#define XF_DST_T XF_10UC3 // XF_8UC3
#define XF_YUV_T XF_16UC1
#elif T_12U
#define XF_SRC_T XF_12UC1 // XF_8UC1
#define XF_LTM_T XF_8UC3  // XF_8UC3
#define XF_DST_T XF_12UC3 // XF_8UC3
#define XF_YUV_T XF_16UC1
#endif

#define SIN_CHANNEL_TYPE XF_8UC1

#define WB_TYPE XF_WB_SIMPLE

#define AEC_EN 0

#define XF_AXI_GBR 1

#define XF_USE_URAM 0 // uram enable
#define XF_CV_DEPTH_3XWIDTH 3 * XF_WIDTH

#define XF_CV_DEPTH_IN 3
#define XF_CV_DEPTH_IN_COPY1 3
#define XF_CV_DEPTH_IN_COPY2 3
#define XF_CV_DEPTH_FULLIR_OUT 3
#define XF_CV_DEPTH_RRGB_OUT 3
#define XF_CV_DEPTH_GAIN_OUT 3
#define XF_CV_DEPTH_DEMOSAIC_OUT 3
#define XF_CV_DEPTH_DEMOOUT_FINAL 3
#define XF_CV_DEPTH_LTM_IN 3
#define XF_CV_DEPTH_DST 3
#define XF_CV_DEPTH_AEC_IN 3
#define XF_CV_DEPTH_OUT 3