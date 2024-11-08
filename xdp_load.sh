#!/bin/bash

# 定义一些变量
EBPF_FILE="xdp_rtps.c"           # eBPF 源代码文件
EBPF_OBJ="xdp_rtps.o"            # 编译生成的字节码文件
NETWORK_INTERFACE="ens33"        # 要加载 eBPF 程序的网络接口

clang -O2 -g -target bpf -c $EBPF_FILE -o $EBPF_OBJ
XDP_LOADED=$(sudo bpftool net show dev $NETWORK_INTERFACE | awk '/xdp:/ { getline; print $0 }')
if [ -n "$XDP_LOADED" ]; then
    echo "卸载之前加载的 XDP 程序"
    sudo ip link set dev $NETWORK_INTERFACE xdpgeneric off
fi
sudo ip link set dev $NETWORK_INTERFACE xdpgeneric obj $EBPF_OBJ sec xdp
sudo ip link show $NETWORK_INTERFACE
