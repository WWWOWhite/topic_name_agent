import os
import subprocess

from flask import Flask, request, jsonify

# 常量定义
CODE_SUCCESS = 200
CODE_FAIL = 500

app = Flask(__name__)

# 增加白名单 
@app.route('/add_guid', methods=['POST'])
def add_guid():
    # 获取guid
    guid = request.json['guid']
    print(guid)
    # 执行载入map脚本
    shell_command = './map_manager /sys/fs/bpf/topic_map add ' +guid + ' 1'
    print(shell_command)
    print(f'str len : {len(guid)}')
    # 阻塞执行播包行为
    result = subprocess.run(shell_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = result.stdout.decode()

    if result.returncode != 0 :
        print(output)
        return jsonify(code=CODE_FAIL, msg=output), 500
    else:
        print(output)
        return jsonify(code=CODE_SUCCESS, msg=output), 200
    
# 增加白名单 
@app.route('/test_add_topic', methods=['POST'])
def test_add_topic():
    # 获取guid
    topic = request.json['topic']
    topic_hex_chars = ''.join(format(ord(char), '02x') for char in topic)

    # 执行载入map脚本
    shell_command = './map_manager /sys/fs/bpf/topic_map add ' +topic_hex_chars + ' 1'
    print(shell_command)
    print(f'str len : {len(topic_hex_chars)}')
    # 阻塞执行安装topic
    result = subprocess.run(shell_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = result.stdout.decode()

    if result.returncode != 0 :
        print(output)
        return jsonify(code=CODE_FAIL, msg=output), 500
    else:
        print(output)
        return jsonify(code=CODE_SUCCESS, msg=output), 200

# 删除白名单
@app.route('/query_map',methods=['GET'])
def query_map():
        # 执行 ./get_map.sh 命令并获取输出
    result = subprocess.run(['./get_map.sh'], stdout=subprocess.PIPE, text=True)

    # 初始化一个列表来存储 key 值
    keys = []

    # 按行处理输出
    for line in result.stdout.splitlines():
        # 查找 'key: ' 开始的行
        if 'key:' in line:
            # 提取 key 值部分，并去掉 'key: ' 前缀
            key_part = line.split('key:')[1].split('value:')[0].strip()
            key_without_spaces = key_part.replace(" ","")
            keys.append(key_without_spaces)
    for key in keys:
        print(key)

    if result.returncode != 0:
        return jsonify(code=CODE_FAIL,msg='查询出错')
    else:
        return jsonify(code=CODE_SUCCESS,data=keys)

@app.route('/delete_guid', methods=['POST'])
def del_guid():
    # 获取guid
    guid = request.json['guid']
    print(guid)
    # 执行载入map脚本
    shell_command = './map_manager /sys/fs/bpf/topic_map del ' +guid

    # 阻塞执行播包行为
    result = subprocess.run(shell_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = result.stdout.decode()

    if result.returncode != 0 :
        print(output)
        return jsonify(code=CODE_FAIL, msg=output), 500
    else:
        print(output)
        return jsonify(code=CODE_SUCCESS, msg=output), 200

# 处理报错
@app.errorhandler(Exception)
def handle_exception(e):
    """处理所有未被捕获的异常"""
    return jsonify(msg=str(e), code=CODE_FAIL), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8890)
