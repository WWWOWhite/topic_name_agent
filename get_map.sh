#!/bin/bash

# 定义一些变量
MAP_NAME="topic_map"           # 定义的 map 名称
MAP_PATH="/sys/fs/bpf/$MAP_NAME" # 文件系统中 map 的路径

MAP_ID=$(sudo bpftool map show | grep "$MAP_NAME" | awk -F: '{print $1}')

sudo bpftool map dump id $MAP_ID

