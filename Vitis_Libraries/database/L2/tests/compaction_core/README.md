# Vitis Tests for compaction acceleration Kernel

**This kernel targets Alveo U200, the makefile does not support other devices.**

To run the test, execute the following command:

```
source /opt/xilinx/Vitis/2020.2/settings64.sh
source /opt/xilinx/xrt/setup.sh
make run TARGET=sw_emu DEVICE=/path/to/<u200>/xpfm
```

`TARGET` can also be `hw_emu`
