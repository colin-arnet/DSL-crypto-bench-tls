============================================
Xilinx Gzip Streaming Quadcore Decompression
============================================

Gzip example resides in ``L2/tests/gzipd_quadcores`` directory. 

Follow build instructions to generate host executable and binary.

The binary host file generated is named as "**xil_zlib**" and it is present in ``./build`` directory.

Executable Usage
----------------

To execute single file for compression 	    : ``./build_dir.<TARGET mode>.<xsa_name>/xil_zlib ./build_dir.<TARGET mode>.<xsa_name>/compress.xclbin  <file_name>``

Results
-------

Resource Utilization 
~~~~~~~~~~~~~~~~~~~~~

Table below presents resource utilization of Xilinx Zlib Decompress
kernels. The final Fmax achieved is 250MHz. 

========== ===== ====== ===== ===== ===== 
Flow       LUT   LUTMem REG   BRAM  URAM 
========== ===== ====== ===== ===== ===== 
Decompress 27.2K 3.1K   20.8K 32    8    
========== ===== ====== ===== ===== ===== 

Performance Data
~~~~~~~~~~~~~~~~

Table below presents kernel throughput achieved for a single compute
unit. 

============================= =========================
Topic                         Results
============================= =========================
Compression Throughput        2 GB/s
============================= =========================

Standard GZip Support
---------------------

This application is compatible with standard Gzip/Zlib application (compress/decompress).  
