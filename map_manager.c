#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <string.h>

#define KEY_SIZE 32

void delete_map_entry(int map_fd, __u8 *key)
{
    int ret = bpf_map_delete_elem(map_fd, key);
    if (ret != 0)
    {
        perror("bpf_map_delete_elem");
        exit(1);
    }
    printf("Successfully deleted map entry with key (GuidPrefix + WriterEntityID)\n");
    for (int i = 0; i < KEY_SIZE; i++)
    {
        printf("%02x", key[i]);
    }
    printf("\n");
}

void print_key(__u8 *key)
{
    printf("Guid:");
    for (int i = 0; i < KEY_SIZE; i++)
    {
        printf("%02x", key[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s <map_path> <add|del> <guid_prefix_writer_entity_id> <value>\n", argv[0]);
        return 1;
    }

    const char *map_path = argv[1];
    const char *operation = argv[2];

    __u8 key[KEY_SIZE] = {0};
    __u32 value;
    int map_fd = bpf_obj_get(map_path);

    if (map_fd < 0)
    {
        perror("Failed to open BPF map");
        return 1;
    }

    if (argc >= 4)
    {
        size_t key_len = strlen(argv[3]);
        if (key_len > KEY_SIZE * 2)
        {
            fprintf(stderr, "Invalid key length. Expected %d hexadecimal characters.\n", KEY_SIZE * 2);
            return 1;
        }

        // 解析 key 的前部分字符
        for (size_t i = 0; i < key_len / 2; i++)
        {
            sscanf(argv[3] + 2 * i, "%2hhx", &key[i]);
        }

        // 手动将未用到的 key 字节清零
        for (size_t i = key_len / 2; i < KEY_SIZE; i++)
        {
            key[i] = 0;
        }
    }

    if (strcmp(operation, "add") == 0)
    {
        if (argc < 5)
        {
            fprintf(stderr, "Usage for add: %s <map_path> add <guid_prefix_writer_entity_id> <value>\n", argv[0]);
            return 1;
        }

        value = atoi(argv[4]);

        // 添加键值对到 map
        int ret = bpf_map_update_elem(map_fd, key, &value, BPF_ANY);
        if (ret != 0)
        {
            perror("bpf_map_update_elem");
            exit(1);
        }
        printf("Successfully load white ");
        print_key(key);
    }
    else if (strcmp(operation, "del") == 0)
    {
        delete_map_entry(map_fd, key);
    }
    else
    {
        fprintf(stderr, "Invalid operation: %s\n", operation);
        return 1;
    }

    close(map_fd);
    return 0;
}
