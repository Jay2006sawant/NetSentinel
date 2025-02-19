#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/string.h>

struct event {
    __u32 source_ip;
    __u32 dest_ip;
    __u16 source_port;
    __u16 dest_port;
    __u8 protocol;
    __u8 pod_namespace[64];
    __u8 pod_name[64];
    __u8 container_id[64];
    __u64 bytes;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    if ((void*)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void*)eth + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    struct event ev = {};
    ev.source_ip = ip->saddr;
    ev.dest_ip = ip->daddr;
    ev.protocol = ip->protocol;
    ev.bytes = data_end - data;
    ev.timestamp = bpf_ktime_get_ns();

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + sizeof(*ip);
        if ((void*)tcp + sizeof(*tcp) <= data_end) {
            ev.source_port = ntohs(tcp->source);
            ev.dest_port = ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + sizeof(*ip);
        if ((void*)udp + sizeof(*udp) <= data_end) {
            ev.source_port = ntohs(udp->source);
            ev.dest_port = ntohs(udp->dest);
        }
    }

    // TODO: Add pod metadata lookup using BPF maps

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return XDP_PASS;
} 