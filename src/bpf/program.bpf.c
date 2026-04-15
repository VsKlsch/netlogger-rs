// bpf/program.bpf.c
#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef AF_INET
    #define AF_INET 2
    #define AF_INET6 10
#endif

// Connect event for transfer into userspace
struct event{
    __u32 pid;
    __u32 tgid;
    __u32 syscall_id;
    __u16 family;
    __u16 port;
    __u8 ip[16];
    __u64 timestamp;
};

struct event _event = {0};

// Map for events
struct {
    __uint (type, BPF_MAP_TYPE_RINGBUF);
    __uint (max_entries, 256 * 1024);
} events SEC(".maps");


// Map for our traced tgids
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u8);
} tracing_tgids SEC(".maps");


// Map for blocked ips
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u8[16]);
    __type(value, __u8);
} blocked_ips SEC(".maps");

volatile const __u32 initial_target_tgid = 0;

static __always_inline int parse_sockaddr(__u64 uservaddr, struct event *e){
    __u16 family;

    if(bpf_probe_read_user(&family, sizeof(family), (void*)uservaddr)){
        return -1;
    }

    e->family = family;

    __builtin_memset(e->ip, 0, sizeof(e->ip));

    if(family == AF_INET){
        if(bpf_probe_read_user(&e->port, sizeof(e->port), (void*)(uservaddr+offsetof(struct sockaddr_in, sin_port)))){
            return -2;
        }
        
        if(bpf_probe_read_user(&e->ip[12], 4, (void*)(uservaddr+offsetof(struct sockaddr_in, sin_addr)))){
            return -2;
        }

        // IPv6 mapped IPv4 addr
        e->ip[10] = 0xff;
        e->ip[11] = 0xff;
    }else if (family == AF_INET6){
        if(bpf_probe_read_user(&e->port, sizeof(e->port), (void*)(uservaddr+offsetof(struct sockaddr_in6, sin6_port)))){
            return -2;
        }
        if(bpf_probe_read_user(e->ip, 16, (void*)(uservaddr+offsetof(struct sockaddr_in6, sin6_addr)))){
            return -2;
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    bool in_map = bpf_map_lookup_elem(&tracing_tgids, &tgid) != NULL;
    bool is_initial = (initial_target_tgid != 0) && (tgid == initial_target_tgid);
    
    if (!in_map && !is_initial){
        return 0;
    }

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e){
        return 0;
    }

    e->pid = (__u32)(pid_tgid);
    e->tgid = tgid;
    e->syscall_id = 1;
    e->timestamp = bpf_ktime_get_ns();

    // Submit packet info if at least family field filled;
    int result = parse_sockaddr(ctx->args[1], e);
    if(result == 0 || result == -2){
        e->port = bpf_ntohs(e->port);
        bpf_ringbuf_submit(e, 0);
    }else{
        bpf_printk("Error when parse packet");
        bpf_ringbuf_discard(e, 0);
    }
    
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx){
    __u32 parent_tgid = ctx->parent_pid;
    __u32 child_tgid = ctx->child_pid;
    const __u8 map_value = 1;

    bool parent_in_map = bpf_map_lookup_elem(&tracing_tgids, &parent_tgid) != NULL;
    bool parent_is_init = (initial_target_tgid != 0) && (parent_tgid == initial_target_tgid);

    if(parent_in_map || parent_is_init){
        bpf_map_update_elem(&tracing_tgids, &child_tgid, &map_value, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_exit *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    bpf_map_delete_elem(&tracing_tgids, &tgid);
    return 0;
}

static __always_inline void ip4_into_ipv6mapped(__u32 ipv4_addr, __u8 ipv6_mapped_addr[16]) {
    __builtin_memset(ipv6_mapped_addr, 0, 16);
    ipv6_mapped_addr[10] = 0xff;
    ipv6_mapped_addr[11] = 0xff;
    __builtin_memcpy(&ipv6_mapped_addr[12], &ipv4_addr, 4);
}

static __always_inline void log_addr(__u8 ipv6_mapped_addr[16]) {
    bpf_printk("IPv4 addr: %x %x %x %x %x %x\n", ipv6_mapped_addr[10], ipv6_mapped_addr[11], ipv6_mapped_addr[12], ipv6_mapped_addr[13], ipv6_mapped_addr[14], ipv6_mapped_addr[15] );
}

#define PASS  1
#define BLOCK 0

SEC("cgroup/connect4")
int connect4_filter(const struct bpf_sock_addr *ctx){
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    bool in_map = bpf_map_lookup_elem(&tracing_tgids, &tgid) != NULL;
    bool is_init = (initial_target_tgid != 0) && (tgid == initial_target_tgid);

    if (!in_map && !is_init){
        return PASS;
    }

    __u8 ipv6_mapped_addr[16];
    ip4_into_ipv6mapped(ctx->user_ip4, ipv6_mapped_addr);

    if(bpf_map_lookup_elem(&blocked_ips, ipv6_mapped_addr) == NULL){
        return PASS;
    }
    return BLOCK;
}

SEC("cgroup/connect6")
int connect6_filter(const struct bpf_sock_addr *ctx){
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    bool in_map = bpf_map_lookup_elem(&tracing_tgids, &tgid) != NULL;
    bool is_init = (initial_target_tgid != 0) && (tgid == initial_target_tgid);

    if (!in_map && !is_init){
        return PASS;
    }

    __u8 ipv6_mapped_addr[16];
    bpf_probe_read_kernel(ipv6_mapped_addr, sizeof(ipv6_mapped_addr), ctx->user_ip6);

    if(bpf_map_lookup_elem(&blocked_ips, ipv6_mapped_addr) == NULL){
        return PASS;
    }
    return BLOCK;
}

char LICENSE[] SEC("license") = "GPL";