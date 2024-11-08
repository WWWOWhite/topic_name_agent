if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <guid> <topic>"
  exit 1
fi

# 从命令行参数中获取 guid 和 topic
guid=$1
topic=$2

# 定义目标 URL
url="http://192.168.19.1:8000/nodemanage/receive-guid/"

# 构建要发送的 JSON 数据
data=$(printf '{"guid":"%s", "topic":"%s"}' "$guid" "$topic")

# 设置 X-Token 的值
token="0ad9e30ca539f968e662b6d505fcd276"

# 发送带有 X-Token 头部的 POST 请求
response=$(curl -s -X POST -H "Content-Type: application/json" -H "X-Token: $token" -d "$data" "$url")

# 输出响应
echo "Response: $response"
