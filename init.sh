#!/bin/bash

# 定义一些变量
EBPF_FILE="xdp_rtps.c"           # eBPF 源代码文件
EBPF_OBJ="xdp_rtps.o"            # 编译生成的字节码文件
MAP_MANAGE="map_manager.c"	# map操作文件源代码
MAP_ELF="map_manager"		# map可执行文件
NETWORK_INTERFACE="ens33"        # 要加载 eBPF 程序的网络接口
MAP_NAME="topic_map"           # 定义的 map 名称
MAP_PATH="/sys/fs/bpf/$MAP_NAME" # 文件系统中 map 的路径

# 1. 编译 eBPF 源代码为字节码文件
echo "编译 eBPF 文件：$EBPF_FILE"
clang -O2 -g -target bpf -c $EBPF_FILE -o $EBPF_OBJ

# 检查并清理之前的 map 固定
if [ -f "$MAP_PATH" ]; then
    echo "清理之前固定的 map：$MAP_PATH"
    sudo rm $MAP_PATH
fi

# 2. 检查是否已有 XDP 程序加载在 ens33 上
echo "检查网络接口 $NETWORK_INTERFACE 上的 XDP 程序状态"
XDP_LOADED=$(sudo bpftool net show dev $NETWORK_INTERFACE | awk '/xdp:/ { getline; print $0 }')

if [ -n "$XDP_LOADED" ]; then
    echo "卸载之前加载的 XDP 程序"
    sudo ip link set dev $NETWORK_INTERFACE xdpgeneric off
fi

# 加载新的 XDP 程序
echo "加载 eBPF 程序到接口 $NETWORK_INTERFACE"
sudo ip link set dev $NETWORK_INTERFACE xdpgeneric obj $EBPF_OBJ sec xdp

# 3. 验证 eBPF 程序是否加载成功
echo "查看网络接口 $NETWORK_INTERFACE 的状态"
sudo ip link show $NETWORK_INTERFACE

# 4. 自动获取 map 的 ID
echo "自动获取 map ID"
MAP_ID=$(sudo bpftool map show | grep "$MAP_NAME" | awk -F: '{print $1}')

# 5. 固定 map 到文件系统
if [ -n "$MAP_ID" ]; then
    echo "固定 map（ID: $MAP_ID）到 $MAP_PATH"
    sudo bpftool map pin id $MAP_ID $MAP_PATH
else
    echo "未找到 map ID，请检查 map 名称和加载状态。"
fi

# 6. 显示固定的 map 结构信息
echo "验证 map 是否固定成功"
ls -l /sys/fs/bpf/ | grep "$MAP_NAME"


# 7. 编译map执行文件
echo "编译map操作文件"
gcc -o $MAP_ELF $MAP_MANAGE -l bpf

# 定义 Flask 使用的端口
FLASK_PORT=8890

# 检查是否有进程正在使用该端口
PID=$(lsof -i tcp:$FLASK_PORT -t)

# 如果存在占用该端口的进程，终止该进程
if [ -n "$PID" ]; then
    echo "发现占用端口 $FLASK_PORT 的进程，进程ID: $PID，正在终止..."
    kill -9 $PID
    echo "进程已终止。"
else
    echo "端口 $FLASK_PORT 未被占用。"
fi
# 8. 执行python程序
# 将输出重定向到带时间戳的日志文件
python3 app.py 

