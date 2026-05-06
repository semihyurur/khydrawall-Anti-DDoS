#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key,   __u32);
    __type(value, __u8);
} ip_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u32);
    __type(value, __u8);
} ip_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key,   __u32);
    __type(value, __u64);
} xdp_stats SEC(".maps");

static __always_inline void bump_counter(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&xdp_stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int xdp_khydrawall(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;


    bump_counter(3);


    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;


    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    __u32 src_ip = ip->saddr;


    __u8 *wl = bpf_map_lookup_elem(&ip_whitelist, &src_ip);
    if (wl)
        return XDP_PASS;


    __u8 *bl = bpf_map_lookup_elem(&ip_blacklist, &src_ip);
    if (bl) {
        bump_counter(0);
        return XDP_DROP;
    }


    __u16 frag_off = bpf_ntohs(ip->frag_off);
    if ((frag_off & 0x1FFF) || (frag_off & 0x2000)) {
        if (bpf_ntohs(ip->tot_len) < 1280) {
            bump_counter(2);
            return XDP_DROP;
        }
    }


    int ihl = ip->ihl * 4;
    if (ihl < 20)
        return XDP_DROP;


    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        __u8 flags = ((__u8 *)tcp)[13];


        if (flags == 0x00) {
            bump_counter(1);
            return XDP_DROP;
        }

        if ((flags & 0x29) == 0x29) {
            bump_counter(1);
            return XDP_DROP;
        }

        if ((flags & 0x03) == 0x03) {
            bump_counter(1);
            return XDP_DROP;
        }

        if ((flags & 0x11) == 0x01) {
            bump_counter(1);
            return XDP_DROP;
        }

        if ((flags & 0x06) == 0x06) {
            bump_counter(1);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
