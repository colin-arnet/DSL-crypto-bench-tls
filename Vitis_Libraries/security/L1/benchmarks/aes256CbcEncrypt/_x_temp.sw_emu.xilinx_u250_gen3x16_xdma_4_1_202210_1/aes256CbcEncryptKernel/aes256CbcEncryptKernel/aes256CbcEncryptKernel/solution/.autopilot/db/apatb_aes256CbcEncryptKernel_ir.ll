; ModuleID = '/home/carnet/crypto-bench-tls/Vitis_Libraries/security/L1/benchmarks/aes256CbcEncrypt/_x_temp.sw_emu.xilinx_u250_gen3x16_xdma_4_1_202210_1/aes256CbcEncryptKernel/aes256CbcEncryptKernel/aes256CbcEncryptKernel/solution/.autopilot/db/a.g.ld.5.gdce.bc'
source_filename = "llvm-link"
target datalayout = "e-m:e-i64:64-i128:128-i256:256-i512:512-i1024:1024-i2048:2048-i4096:4096-n8:16:32:64-S128-v16:16-v24:32-v32:32-v48:64-v96:128-v192:256-v256:256-v512:512-v1024:1024"
target triple = "fpga64-xilinx-none"

%"struct.ap_uint<128>" = type { %"struct.ap_int_base<128, false>" }
%"struct.ap_int_base<128, false>" = type { %"struct.ssdm_int<128, false>" }
%"struct.ssdm_int<128, false>" = type { i128 }

; Function Attrs: noinline
define void @apatb_aes256CbcEncryptKernel_ir(%"struct.ap_uint<128>"* noalias nocapture nonnull readonly %inputData, %"struct.ap_uint<128>"* noalias nocapture nonnull %outputData) local_unnamed_addr #0 {
entry:
  %inputData_copy = alloca %"struct.ap_uint<128>", align 512
  %outputData_copy = alloca %"struct.ap_uint<128>", align 512
  call fastcc void @copy_in(%"struct.ap_uint<128>"* nonnull %inputData, %"struct.ap_uint<128>"* nonnull align 512 %inputData_copy, %"struct.ap_uint<128>"* nonnull %outputData, %"struct.ap_uint<128>"* nonnull align 512 %outputData_copy)
  call void @apatb_aes256CbcEncryptKernel_hw(%"struct.ap_uint<128>"* %inputData_copy, %"struct.ap_uint<128>"* %outputData_copy)
  call void @copy_back(%"struct.ap_uint<128>"* %inputData, %"struct.ap_uint<128>"* %inputData_copy, %"struct.ap_uint<128>"* %outputData, %"struct.ap_uint<128>"* %outputData_copy)
  ret void
}

; Function Attrs: argmemonly noinline norecurse
define internal fastcc void @copy_in(%"struct.ap_uint<128>"* noalias readonly, %"struct.ap_uint<128>"* noalias align 512, %"struct.ap_uint<128>"* noalias readonly, %"struct.ap_uint<128>"* noalias align 512) unnamed_addr #1 {
entry:
  call fastcc void @"onebyonecpy_hls.p0struct.ap_uint<128>"(%"struct.ap_uint<128>"* align 512 %1, %"struct.ap_uint<128>"* %0)
  call fastcc void @"onebyonecpy_hls.p0struct.ap_uint<128>"(%"struct.ap_uint<128>"* align 512 %3, %"struct.ap_uint<128>"* %2)
  ret void
}

; Function Attrs: argmemonly noinline norecurse
define internal fastcc void @"onebyonecpy_hls.p0struct.ap_uint<128>"(%"struct.ap_uint<128>"* noalias align 512, %"struct.ap_uint<128>"* noalias readonly) unnamed_addr #2 {
entry:
  %2 = icmp eq %"struct.ap_uint<128>"* %0, null
  %3 = icmp eq %"struct.ap_uint<128>"* %1, null
  %4 = or i1 %2, %3
  br i1 %4, label %ret, label %copy

copy:                                             ; preds = %entry
  %.0.0.04 = getelementptr %"struct.ap_uint<128>", %"struct.ap_uint<128>"* %1, i32 0, i32 0, i32 0, i32 0
  %.01.0.05 = getelementptr %"struct.ap_uint<128>", %"struct.ap_uint<128>"* %0, i32 0, i32 0, i32 0, i32 0
  %5 = load i128, i128* %.0.0.04, align 16
  store i128 %5, i128* %.01.0.05, align 512
  br label %ret

ret:                                              ; preds = %copy, %entry
  ret void
}

; Function Attrs: argmemonly noinline norecurse
define internal fastcc void @copy_out(%"struct.ap_uint<128>"* noalias, %"struct.ap_uint<128>"* noalias readonly align 512, %"struct.ap_uint<128>"* noalias, %"struct.ap_uint<128>"* noalias readonly align 512) unnamed_addr #3 {
entry:
  call fastcc void @"onebyonecpy_hls.p0struct.ap_uint<128>"(%"struct.ap_uint<128>"* %0, %"struct.ap_uint<128>"* align 512 %1)
  call fastcc void @"onebyonecpy_hls.p0struct.ap_uint<128>"(%"struct.ap_uint<128>"* %2, %"struct.ap_uint<128>"* align 512 %3)
  ret void
}

declare void @apatb_aes256CbcEncryptKernel_hw(%"struct.ap_uint<128>"*, %"struct.ap_uint<128>"*)

; Function Attrs: argmemonly noinline norecurse
define internal fastcc void @copy_back(%"struct.ap_uint<128>"* noalias, %"struct.ap_uint<128>"* noalias readonly align 512, %"struct.ap_uint<128>"* noalias, %"struct.ap_uint<128>"* noalias readonly align 512) unnamed_addr #3 {
entry:
  call fastcc void @"onebyonecpy_hls.p0struct.ap_uint<128>"(%"struct.ap_uint<128>"* %2, %"struct.ap_uint<128>"* align 512 %3)
  ret void
}

define void @aes256CbcEncryptKernel_hw_stub_wrapper(%"struct.ap_uint<128>"*, %"struct.ap_uint<128>"*) #4 {
entry:
  call void @copy_out(%"struct.ap_uint<128>"* null, %"struct.ap_uint<128>"* %0, %"struct.ap_uint<128>"* null, %"struct.ap_uint<128>"* %1)
  call void @aes256CbcEncryptKernel_hw_stub(%"struct.ap_uint<128>"* %0, %"struct.ap_uint<128>"* %1)
  call void @copy_in(%"struct.ap_uint<128>"* null, %"struct.ap_uint<128>"* %0, %"struct.ap_uint<128>"* null, %"struct.ap_uint<128>"* %1)
  ret void
}

declare void @aes256CbcEncryptKernel_hw_stub(%"struct.ap_uint<128>"*, %"struct.ap_uint<128>"*)

attributes #0 = { noinline "fpga.wrapper.func"="wrapper" }
attributes #1 = { argmemonly noinline norecurse "fpga.wrapper.func"="copyin" }
attributes #2 = { argmemonly noinline norecurse "fpga.wrapper.func"="onebyonecpy_hls" }
attributes #3 = { argmemonly noinline norecurse "fpga.wrapper.func"="copyout" }
attributes #4 = { "fpga.wrapper.func"="stub" }

!llvm.dbg.cu = !{}
!llvm.ident = !{!0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0, !0}
!llvm.module.flags = !{!1, !2, !3}
!blackbox_cfg = !{!4}

!0 = !{!"clang version 7.0.0 "}
!1 = !{i32 2, !"Dwarf Version", i32 4}
!2 = !{i32 2, !"Debug Info Version", i32 3}
!3 = !{i32 1, !"wchar_size", i32 4}
!4 = !{}
