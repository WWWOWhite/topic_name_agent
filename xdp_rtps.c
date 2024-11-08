#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <netinet/in.h>

#define RTPS_HEADER_SIZE 20
#define INFO_TS_SIZE 12
#define INFO_DST_SIZE 16
#define DATA_BEFOR_SERIALIZED_SIZE 28
#define GUID_PREFIX_OFFSET 8
#define GUID_PREFIX_SIZE 12
#define WRITER_ENTITY_ID_OFFSET 12
#define WRITER_ENTITY_ID_SIZE 4
#define INFO_TS_SUBMESSAGE_ID 0x09
#define DATA_SUBMESSAGE_ID 0x15
#define INFO_DST_SUBMESSAGE_ID 0x0e

#define PID_TOPIC_NAME 0x0005
#define MAX_STRING_LEN 31             // 最大字符串长度
#define KEY_SIZE (MAX_STRING_LEN + 1) // +1 用于存储结束符

// #define PUB_KEY_SIZE 36

struct bpf_map_def SEC("maps") topic_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = KEY_SIZE,        // 字符串最大长度为31字节 + 1字节的 '\0'
    .value_size = sizeof(__u32), // 假设我们存储的是一个 __u32 类型的值
    .max_entries = 1024,         // 设置最大条目数
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    __u32 *stored_value;
    __u32 *pub_value;
    __u8 topic_name[KEY_SIZE];      // +1 for null terminator
    __u8 real_topic_name[KEY_SIZE]; // 新的 topic name，只包含有效的部分
    __u8 ip_topic[KEY_SIZE];        // 用于存储ip和real_topic_name

    // 检查以太网头边界
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 检查以太网协议类型
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 获取 IP 头，并检查边界
    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 检查是否为 UDP 协议
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // 获取 UDP 头，并检查边界
    udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // 解析 RTPS 数据包
    void *rtps_data = (void *)udp + sizeof(*udp);
    if ((void *)(rtps_data + RTPS_HEADER_SIZE + INFO_TS_SIZE) > data_end)
        return XDP_PASS;

    // 检查是否为 RTPS 数据包
    __u8 *rtps_header = (__u8 *)rtps_data;
    if ((void *)(rtps_header + 4) > data_end)
        return XDP_PASS;

    if (rtps_header[0] != 'R' || rtps_header[1] != 'T' || rtps_header[2] != 'P' || rtps_header[3] != 'S')
        return XDP_PASS;

    // 判断第一个submessage是否为INFO_DST
    __u8 *submessage = (__u8 *)(rtps_data + RTPS_HEADER_SIZE);
    if ((void *)(submessage + 1) > data_end)
        return XDP_PASS;
    if (*submessage == INFO_TS_SUBMESSAGE_ID)
    {
        if ((void *)(rtps_data + RTPS_HEADER_SIZE + INFO_TS_SIZE + WRITER_ENTITY_ID_OFFSET + WRITER_ENTITY_ID_SIZE) > data_end)
            return XDP_PASS;

        __u32 writer_entity_id = *((__u32 *)(rtps_data + RTPS_HEADER_SIZE + INFO_TS_SIZE + WRITER_ENTITY_ID_OFFSET));
        // 检查 WriterEntityID 是否为SEDP报文
        if (writer_entity_id != htonl(0x000003C2))
        {
            return XDP_PASS;
        }
        if ((void *)(rtps_header + 88 + 32) > data_end) // 确保后续比较时不越界
        {
            return XDP_PASS;
        }

        // topic name的长度的位置为rtps_headr + 84 ,长度为4个字节
        __u32 *topic_length = (__u32 *)(rtps_header + 84);

        // 确保 topic_length 不超过最大长度
        if (*topic_length > MAX_STRING_LEN)
            return XDP_PASS;

        // 验证是否
        __builtin_memcpy(topic_name, rtps_header + 88, KEY_SIZE); // topic name 紧随其后
        __builtin_memset(real_topic_name, 0, KEY_SIZE);           // 初始化为 0
        unsigned int j = 0;
        for (int i = 0; i < KEY_SIZE; i++)
        {
            if (topic_name[i] == '\0')
            {
                break;
            }
            real_topic_name[j++] = topic_name[i]; // 将有效部分复制到新数组
        }
        bpf_printk("real_topic_name  %x", real_topic_name);
        for (int i = 0; i < KEY_SIZE; i++)
        {
            if (real_topic_name[i] == '\0')
            {
                break;
            }
            bpf_printk("real_topic_name[%d]: %c", i, real_topic_name[i]); // 打印每个字符
        }
        // 检查 topic_name 是否存在于 map 中
        stored_value = bpf_map_lookup_elem(&topic_map, real_topic_name);
        if (stored_value)
        {
            // 如果 topic_name 存在，允许通过
            bpf_printk("stored_value : %x", stored_value);
        }
        else
        {
            // 如果 topic_name 不存在，丢弃数据包
            bpf_printk("stored_value don't exist: %x", stored_value);
            return XDP_DROP;
        }
        // 将ip拷贝到ip_topic的前四个字符，将real_topic_name字符紧随其后加载ip_topic后
        // 组合 IP 地址和 real_topic_name
        __builtin_memset(ip_topic, 0, KEY_SIZE);
        __builtin_memcpy(ip_topic, &ip->saddr, 4);                     // 拷贝 IP 地址的前 4 个字节
        __builtin_memcpy(ip_topic + 4, real_topic_name, KEY_SIZE - 4); // 将 real_topic_name 加到 ip_topic 后
        // 检查 ip_topic 是否存在于map中
        pub_value = bpf_map_lookup_elem(&topic_map, ip_topic);
        if (!pub_value)
        {
            bpf_printk("ip_topic 不存在, %x", ip_topic);
            return XDP_DROP;
        }
        else
        {
            bpf_printk("ip_topic 存在 %x", ip_topic);
            bpf_printk("pub_value : %x", pub_value);
        }
    }
    else if (*submessage == INFO_DST_SUBMESSAGE_ID)
    {
        submessage += INFO_DST_SIZE;
        if ((void *)(submessage + 1) > data_end)
        {

            return XDP_PASS;
        }
        if (*submessage == DATA_SUBMESSAGE_ID)
        {
            if ((void *)(rtps_data + RTPS_HEADER_SIZE + INFO_DST_SIZE + WRITER_ENTITY_ID_OFFSET + WRITER_ENTITY_ID_SIZE) > data_end)
                return XDP_PASS;

            __u32 writer_entity_id = *((__u32 *)(rtps_data + RTPS_HEADER_SIZE + INFO_DST_SIZE + WRITER_ENTITY_ID_OFFSET));
            // 检查 WriterEntityID 是否为SEDP报文
            if (writer_entity_id != htonl(0x000003C2))
            {
                return XDP_PASS;
            }
            if ((void *)(rtps_header + 88 + 4 + 32) > data_end) // 确保后续比较时不越界
            {
                return XDP_PASS;
            }

            // topic name的长度的位置为rtps_headr + 84 ,长度为4个字节
            __u32 *topic_length = (__u32 *)(rtps_header + 84 + 4);

            // 确保 topic_length 不超过最大长度
            if (*topic_length > MAX_STRING_LEN)
                return XDP_PASS;

            // 验证是否
            __builtin_memcpy(topic_name, rtps_header + 88 + 4, KEY_SIZE); // topic name 紧随其后
            __builtin_memset(real_topic_name, 0, KEY_SIZE);               // 初始化为 0
            unsigned int j = 0;
            for (int i = 0; i < KEY_SIZE; i++)
            {
                if (topic_name[i] == '\0')
                {
                    break;
                }
                real_topic_name[j++] = topic_name[i]; // 将有效部分复制到新数组
            }
            bpf_printk("real_topic_name  %x", real_topic_name);
            for (int i = 0; i < KEY_SIZE; i++)
            {
                if (real_topic_name[i] == '\0')
                {
                    break;
                }
                bpf_printk("real_topic_name[%d]: %c", i, real_topic_name[i]); // 打印每个字符
            }
            // 检查 topic_name 是否存在于 map 中
            stored_value = bpf_map_lookup_elem(&topic_map, real_topic_name);
            if (stored_value)
            {
                // 如果 topic_name 存在，允许通过
                bpf_printk("topic exist , stored_value : %x", stored_value);
            }
            else
            {
                // 如果 topic_name 不存在，丢弃数据包
                bpf_printk("stored_value don't exist: %x", stored_value);
                return XDP_DROP;
            }
            // 将ip拷贝到ip_topic的前四个字符，将real_topic_name字符紧随其后加载ip_topic后
            // 组合 IP 地址和 real_topic_name
            __builtin_memset(ip_topic, 0, KEY_SIZE);
            __builtin_memcpy(ip_topic, &ip->saddr, 4);                     // 拷贝 IP 地址的前 4 个字节
            __builtin_memcpy(ip_topic + 4, real_topic_name, KEY_SIZE - 4); // 将 real_topic_name 加到 ip_topic 后
            for (int i = 0; i < KEY_SIZE; i++)
            {
                bpf_printk("ip_topic[%d]: %02x", i, ip_topic[i]);
            }
            bpf_printk("ip_topic: %s", ip_topic);

            // 检查 ip_topic 是否存在于map中
            pub_value = bpf_map_lookup_elem(&topic_map, ip_topic);

            if (!pub_value)
            {
                bpf_printk("ip_topic dont exist, %x", ip_topic);
                return XDP_DROP;
            }
            else
            {
                bpf_printk("ip_topic exist %x", ip_topic);
                bpf_printk("pub_value : %x", pub_value);
                return XDP_PASS;
            }
        }
        else
        {
            if (*submessage != INFO_TS_SUBMESSAGE_ID)
            {
                // bpf_printk("submesssage after dst : %x", *submessage);
                return XDP_PASS;
            }
            else
            {
                bpf_printk("afrer ts");
            }
            // 判断第三个submessage是否为DATA
            submessage += INFO_TS_SIZE;
            if ((void *)(submessage + 1) > data_end)
                return XDP_PASS;

            // bpf_printk("after dst and ts %x", *submessage);
            if (*submessage != DATA_SUBMESSAGE_ID)
            {
                // bpf_printk(" after dst and ts is not data");
                return XDP_PASS;
            }

            // 提取serialized_data
            if ((void *)(rtps_header + 104 + 32) > data_end) // +7确保后续比较时不越界
            {
                // bpf_printk("+104 ");
                return XDP_PASS;
            }
            // topic name的长度的位置为rtps_headr + 100 ,长度为4个字节
            __u32 *topic_length = (__u32 *)(rtps_header + 100);
            if (*topic_length > KEY_SIZE)
            {
                return XDP_PASS;
            }

            // 使用 __builtin_memcpy 来替代 memcpy
            __builtin_memcpy(topic_name, rtps_header + 104, KEY_SIZE); // topic name 紧随其后
            __builtin_memset(real_topic_name, 0, KEY_SIZE);            // 初始化为 0
            unsigned int j = 0;
            for (int i = 0; i < KEY_SIZE; i++)
            {
                if (topic_name[i] == '\0')
                {
                    break;
                }
                real_topic_name[j++] = topic_name[i];
            }
            for (int i = 0; i < KEY_SIZE; i++)
            {
                bpf_printk("ip_topic[%d]: %02x", i, ip_topic[i]);
            }
            bpf_printk("real_topic_name  %x", real_topic_name);
            // 检查 topic_name 是否存在于 map 中
            stored_value = bpf_map_lookup_elem(&topic_map, real_topic_name);
            if (stored_value)
            {
                // 如果 topic_name 存在，允许通过
                bpf_printk("stored_value : %x", stored_value);
            }
            else
            {
                // 如果 topic_name 不存在，丢弃数据包
                bpf_printk("stored_value don't exist: %x", stored_value);
                return XDP_DROP;
            }
            __builtin_memset(ip_topic, 0, KEY_SIZE);
            __builtin_memcpy(ip_topic, &ip->saddr, 4);                     // 拷贝 IP 地址的前 4 个字节
            __builtin_memcpy(ip_topic + 4, real_topic_name, KEY_SIZE - 4); // 将 real_topic_name 加到 ip_topic 后
            // 检查 ip_topic 是否存在于map中
            pub_value = bpf_map_lookup_elem(&topic_map, ip_topic);
            if (!pub_value)
            {
                bpf_printk("ip_topic 不存在, %x", ip_topic);
                return XDP_DROP;
            }
            else
            {
                bpf_printk("ip_topic 存在 %x", ip_topic);
                bpf_printk("pub_value : %x", pub_value);
            }
        }
    }
    else
    {
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
