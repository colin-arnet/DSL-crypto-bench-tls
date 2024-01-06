.. 
   Copyright 2019 Xilinx, Inc.
  
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
  
       http://www.apache.org/licenses/LICENSE-2.0
  
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.


.. Project documentation master file, created by
   sphinx-quickstart on Thu Jun 20 14:04:09 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

==========
Benchmark 
==========
    

Performance Summary for APIs
-----------

.. table:: Table 1 Summary table for performance and resources of APIs
    :align: center

+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  API                         | Type  | Input Description      | FPS   | MB/s   | MP/s  | Freq.  | LUT    | BRAM| URAM| DSP   |
+==============================+=======+========================+=======+========+=======+========+========+=====+=====+=======+
|  pikEncKernel1Top            | HW    | lena_c_512.jpg         |  62.5 |        |  16.4 | 200MHz |  97.4k |  25 |  93 |  568  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  pikEncKernel2Top            | HW    | lena_c_512.jpg         |  62.5 |        |  16.4 | 200MHz | 262.5k | 411 | 252 | 1614  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  pikEncKernel3Top            | HW    | lena_c_512.jpg         |  62.5 |        |  16.4 | 200MHz |  90.0k | 178 | 128 |  216  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  pikEncKernel1Top            | HW    | lena_c_2048.png        |   5.2 |        |    22 | 200MHz |  97.4k |  25 |  93 |  568  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  pikEncKernel2Top            | HW    | lena_c_2048.png        |   5.2 |        |    22 | 200MHz | 262.5k | 411 | 252 | 1614  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  pikEncKernel3Top            | HW    | lena_c_2048.png        |   5.2 |        |    22 | 200MHz |  90.0k | 178 | 128 |  216  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  kernelJpegDecoderTop        | HW    | lena_c_512.jpg         |  1148 | 87.0   |       | 243MHz |  23.1k |  28 |   0 |   39  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  resizeTop(NP=8)             | HW    | 7680*4320 to 512*512   |  79.7 | 2644.3 |       | 341MHz |  15.0k |  29 |   0 |  168  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  resizeTop(NP=8)             | HW    | 7680*4320 to 1920*1080 |  80.5 | 2670.8 |       | 341MHz |  15.0k |  29 |   0 |  168  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  webp_IntraPredLoop2_NoOut_1 | HW    | lena_c_512.png         |       | 127.17 |       | 250MHz |  52.9k |  72 |  10 |  410  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  webp_2_ArithmeticCoding_1   | HW    | lena_c_512.png         |       | 127.17 |       | 250MHz |  15.9k | 157 |   0 |    4  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  webp_IntraPredLoop2_NoOut_1 | HW    | 1920x1080.png          |       | 172.54 |       | 250MHz |  52.9k |  72 |  10 |  410  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  webp_2_ArithmeticCoding_1   | HW    | 1920x1080.png          |       | 172.54 |       | 250MHz |  15.9k | 157 |   0 |    4  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  JxlEnc_ans_clusterHistogram | HW    | lena_c_512.png         |       |        |  56.9 | 291MHz |  38.5K |  70 |  28 |   51  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  JxlEnc_lossy_enc_compute    | HW    | lena_c_512.png         |       |        |  72.2 | 260MHz | 121.7K | 364 |  53 |  498  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  JxlEnc_ans_initHistogram    | HW    | lena_c_512.png         |       |        |  43.2 | 289MHz |  39.3K |  50 |  41 |   95  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  JxlEnc_ans_clusterHistogram | HW    | hq_2Kx2K.png           |       |        | 101.9 | 291MHz |  38.5K |  70 |  28 |   51  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  JxlEnc_lossy_enc_compute    | HW    | hq_2Kx2K.png           |       |        |  83.3 | 260MHz | 121.7K | 364 |  53 |  498  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  JxlEnc_ans_initHistogram    | HW    | hq_2Kx2K.png           |       |        |  52.9 | 289MHz |  39.3K |  50 |  41 |   95  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+
|  jpegHuffmanDecoder          | cosim | lena_c_512.jpg         |  2288 |    174 |       | 270MHz |   7.9K |   5 |   0 |    2  |
+------------------------------+-------+------------------------+-------+--------+-------+--------+--------+-----+-----+-------+


These are details for benchmark result and usage steps.

.. toctree::
   :maxdepth: 1

   benchmark/jpegHuffmanDecoderIP.rst
   benchmark/jpegDecoder.rst
   benchmark/pikEnc.rst
   benchmark/resize.rst
   benchmark/webpEnc.rst
   benchmark/jxlEnc.rst

Test Overview
--------------

Here are benchmarks of the Vitis Codec Library using the Vitis environment and comparing with cpu(). 


.. _l2_vitis_codec:

Vitis Codec Library
~~~~~~~~~~~~~~~~~~~

* **Download code**

These graph benchmarks can be downloaded from `vitis libraries <https://github.com/Xilinx/Vitis_Libraries.git>`_ ``master`` branch.

.. code-block:: bash

   git clone https://github.com/Xilinx/Vitis_Libraries.git 
   cd Vitis_Libraries
   git checkout master
   cd codec 

* **Setup environment**

Specifying the corresponding Vitis, XRT, and path to the platform repository by running following commands.

.. code-block:: bash

   source <intstall_path>/installs/lin64/Vitis/2022.1/settings64.sh
   source /opt/xilinx/xrt/setup.sh
   export PLATFORM_REPO_PATHS=/opt/xilinx/platforms
