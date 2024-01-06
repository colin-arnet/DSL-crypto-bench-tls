catch {::common::set_param -quiet hls.xocc.mode csynth};
catch {::common::set_param -quiet hls.enable_scout_hidden_option_error false};
# 
# HLS run script generated by v++ compiler
# 

open_project aes256CbcEncryptKernel
set_top aes256CbcEncryptKernel
# v++ -g, -D, -I, --advanced.prop kernel.aes256CbcEncryptKernel.kernel_flags
add_files "/home/carnet/crypto-bench-tls/Vitis_Libraries/security/L1/benchmarks/aes256CbcEncrypt/kernel/aes256CbcEncryptKernel.cpp" -cflags " -I /home/carnet/crypto-bench-tls/Vitis_Libraries/security/L1/include -I /home/carnet/crypto-bench-tls/Vitis_Libraries/security/L1/benchmarks/aes256CbcEncrypt/kernel -I /home/carnet/crypto-bench-tls/Vitis_Libraries/security/L1/include -I /home/carnet/crypto-bench-tls/Vitis_Libraries/security/L1/benchmarks/aes256CbcEncrypt/kernel"
open_solution -flow_target vitis solution
set_part xcu250-figd2104-2L-e
# v++ --hls.clock or --kernel_frequency
create_clock -period 300MHz -name default
# v++ --advanced.param compiler.hlsDataflowStrictMode
config_dataflow -strict_mode warning
# v++ --advanced.param compiler.deadlockDetection
config_export -deadlock_detection none
# v++ --advanced.param compiler.axiDeadLockFree
config_interface -m_axi_conservative_mode=1
config_interface -m_axi_addr64
# v++ --hls.max_memory_ports
config_interface -m_axi_auto_max_ports=0
config_export -format xo -ipname aes256CbcEncryptKernel
catch {::common::set_param -quiet hls.enable_synthesis_check_sw_only true};
csynth_design -synthesis_check
close_project
puts "HLS completed successfully"
exit