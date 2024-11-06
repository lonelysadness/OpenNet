#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

// Define SEC macro if not defined
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// Add TCP flags definitions
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

struct connection_info_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 is_outgoing;    // New field to track direction
    __u8 tcp_flags;    // New field for TCP flags
    __u16 payload_len; // New field for payload length
    __u32 pid;        // Add PID field
    __u32 uid;        // Add UID field
    __u32 inode;      // Add inode field
};

// Add a new map for connection tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct connection_info_t);
    __type(value, __u64);
} connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

// Helper functions for socket lookup
static __always_inline struct bpf_sock *lookup_tcp_sock(struct xdp_md *ctx, 
    void *tuple, int size) {
    return bpf_sk_lookup_tcp(ctx, tuple, size, BPF_F_CURRENT_CPU, 0);
}

static __always_inline struct bpf_sock *lookup_udp_sock(struct xdp_md *ctx, 
    void *tuple, int size) {
    return bpf_sk_lookup_udp(ctx, tuple, size, BPF_F_CURRENT_CPU, 0);
}

SEC("xdp")
int capture_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    struct connection_info_t conn_info = {};
    conn_info.src_ip = ip->saddr;
    conn_info.dst_ip = ip->daddr;
    conn_info.protocol = ip->protocol;
    conn_info.payload_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4);
    
    // Set is_outgoing flag based on source IP being local
    // Note: You might want to add more sophisticated local IP detection
    conn_info.is_outgoing = 1;  // Default to outgoing for now

    struct bpf_sock_tuple tuple = {};
    struct bpf_sock *sk = NULL;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)(ip + 1);
        if ((void*)(tcp + 1) > data_end)
            return XDP_PASS;
        
        conn_info.src_port = bpf_ntohs(tcp->source);
        conn_info.dst_port = bpf_ntohs(tcp->dest);
        
        // Fix TCP flags access
        conn_info.tcp_flags = 0;
        if (tcp->fin) conn_info.tcp_flags |= TCP_FIN;
        if (tcp->syn) conn_info.tcp_flags |= TCP_SYN;
        if (tcp->rst) conn_info.tcp_flags |= TCP_RST;
        if (tcp->psh) conn_info.tcp_flags |= TCP_PSH;
        if (tcp->ack) conn_info.tcp_flags |= TCP_ACK;
        if (tcp->urg) conn_info.tcp_flags |= TCP_URG;
        
        // Block SYN+RST combination
        if ((conn_info.tcp_flags & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST))
            return XDP_DROP;

        tuple.ipv4.saddr = ip->saddr;
        tuple.ipv4.daddr = ip->daddr;
        tuple.ipv4.sport = tcp->source;
        tuple.ipv4.dport = tcp->dest;
        sk = lookup_tcp_sock(ctx, &tuple, sizeof(tuple.ipv4));
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)(ip + 1);
        if ((void*)(udp + 1) > data_end)
            return XDP_PASS;
        
        conn_info.src_port = bpf_ntohs(udp->source);
        conn_info.dst_port = bpf_ntohs(udp->dest);

        tuple.ipv4.saddr = ip->saddr;
        tuple.ipv4.daddr = ip->daddr;
        tuple.ipv4.sport = udp->source;
        tuple.ipv4.dport = udp->dest;
        sk = lookup_udp_sock(ctx, &tuple, sizeof(tuple.ipv4));
    } else if (ip->protocol == IPPROTO_ICMP) {
        // Block ICMP packets to specific IP
        if (ip->daddr == bpf_htonl(0x9df00101)) { // 157.240.1.1 in hex
            return XDP_DROP;
        }
    }

    if (sk) {
        // Fix socket info access
        // Note: We might not be able to get PID/UID directly from bpf_sock
        // Setting them to 0 as fallback
        conn_info.pid = 0;
        conn_info.uid = 0;
        bpf_sk_release(sk);
    }

    // Send connection info to userspace for verdict
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &conn_info, sizeof(conn_info));

    // Check if connection is already tracked
    __u64 *seen = bpf_map_lookup_elem(&connections, &conn_info);
    if (seen) {
        // If connection exists in map, it was allowed
        return XDP_PASS;
    }

    // For new connections, default to PASS and let userspace decide
    // Userspace will add to connections map if allowed
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
