// bpf/program.bpf.c
#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Family constants
#ifndef AF_INET
    #define AF_INET 2
    #define AF_INET6 10
    #define AF_UNIX 16
#endif

// Base profile types
#define BASE_PROFILE_DENY_ALL 0
#define BASE_PROFILE_PASS_ALL 1

// Event status
#define EVENT_STATUS_BLOCK 0
#define EVENT_STATUS_PASS 1

// Cgroup filter result
#define CGROUP_FILTER_RESULT_BLOCK 0
#define CGROUP_FILTER_RESULT_PASS 1

// L4 protocol
#define L4_PROTOCOL_TCP 0
#define L4_PROTOCOL_UDP 1
#define L4_PROTOCOL_OTHER 255

// Parse Status
#define PARSE_STATUS_SUCCESS 0
#define PARSE_STATUS_ERROR_UNKNOWN_FAMILY 1

// SOCKET TYPE

#define SOCK_STREAM 1
#define SOCK_DGRAM 2

// Connect event for transfer into userspace
struct event{
    __u32 pid;
    __u32 tgid;
    __u16 family;
    __u16 port;
    __u8 ip[16];
    __u64 timestamp;
    __u8 event_status;
    __u8 l4_protocol;
    __u8 parse_status;
    __u8 _padding[5];
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
} ip_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} profile_mode SEC(".maps");

volatile const __u32 initial_target_tgid = 0;
volatile const __u8 fallback_profile = BASE_PROFILE_DENY_ALL;

static __always_inline void ip4_into_ipv6mapped(__u32 ipv4_addr, __u8 ipv6_mapped_addr[16]) {
    __builtin_memset(ipv6_mapped_addr, 0, 16);
    ipv6_mapped_addr[10] = 0xff;
    ipv6_mapped_addr[11] = 0xff;
    __builtin_memcpy(&ipv6_mapped_addr[12], &ipv4_addr, 4);
}

static __always_inline void fill_event_struct(struct event *e, __u64 pid_tgid, __u8 l4_protocol, __u8 family){
    __u32 tgid = (__u32)(pid_tgid >> 32);

    e->pid = (__u32)(pid_tgid);
    e->tgid = tgid;
    e->timestamp = bpf_ktime_get_ns();
    e->l4_protocol = l4_protocol;
    e->family = family;

    __builtin_memset(e->ip, 0, sizeof(e->ip));
}

static __always_inline void parse_sockaddr(const struct bpf_sock_addr *ctx, struct event *e, __u8 family){
    e->port = bpf_ntohs(ctx->user_port);
    if(family == AF_INET){
        ip4_into_ipv6mapped(ctx->user_ip4, e->ip);
        e->parse_status = PARSE_STATUS_SUCCESS;
    }else if (family == AF_INET6){
        bpf_probe_read_kernel(e->ip, sizeof(e->ip), ctx->user_ip6);
        e->parse_status = PARSE_STATUS_SUCCESS;
    }else if (family == AF_UNIX){
        e->parse_status = PARSE_STATUS_SUCCESS;
    }else{
        e->parse_status = PARSE_STATUS_ERROR_UNKNOWN_FAMILY;
    }
}

static __always_inline int check_and_block(const struct bpf_sock_addr *ctx, __u8 family, __u8 l4_protocol) {
    __u64 tgid_pid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(tgid_pid >> 32);

    bool in_map = bpf_map_lookup_elem(&tracing_tgids, &tgid) != NULL;
    bool is_init = (initial_target_tgid != 0) && (tgid == initial_target_tgid);

    if (!in_map && !is_init){
        return CGROUP_FILTER_RESULT_PASS;
    }

    struct event e;
    fill_event_struct(&e, tgid_pid, l4_protocol, family);

    parse_sockaddr(ctx, &e, family);

    bool is_in_list = false;
    if(bpf_map_lookup_elem(&ip_list, e.ip) != NULL){
        is_in_list = true;
    }    

    const __u32 key = 0;

    __u8 *profile_ptr = (__u8*)bpf_map_lookup_elem(&profile_mode, &key);
    __u8 profile = profile_ptr == NULL ? fallback_profile : *profile_ptr;

    bool block = (profile == BASE_PROFILE_PASS_ALL) ? is_in_list : !is_in_list;

    e.event_status = block ? EVENT_STATUS_BLOCK : EVENT_STATUS_PASS;

    struct event *event_in_ringbuf;
    event_in_ringbuf = bpf_ringbuf_reserve(&events, sizeof(e), 0);
    if(event_in_ringbuf){
        __builtin_memcpy(event_in_ringbuf, &e, sizeof(struct event));
        bpf_ringbuf_submit(event_in_ringbuf, 0);
    }else{
        bpf_printk("[Lost event] Error when try to load event to ringbuf.");
    }

    return block ? CGROUP_FILTER_RESULT_BLOCK : CGROUP_FILTER_RESULT_PASS;
}

static __always_inline __u8 get_l4_protocol_by_socket_type(const struct bpf_sock_addr *ctx) {
    if(ctx->type == SOCK_STREAM){
        return L4_PROTOCOL_TCP;
    }else if (ctx->type == SOCK_DGRAM){
        return L4_PROTOCOL_UDP;
    }
    return L4_PROTOCOL_OTHER;
}


SEC("cgroup/connect4")
int connect4_filter(const struct bpf_sock_addr *ctx){
    return check_and_block(ctx, AF_INET, get_l4_protocol_by_socket_type(ctx));
}

SEC("cgroup/connect6")
int connect6_filter(const struct bpf_sock_addr *ctx){
    return check_and_block(ctx, AF_INET6, get_l4_protocol_by_socket_type(ctx));
}

SEC("cgroup/sendmsg4")
int sendmsg4_filter(const struct bpf_sock_addr *ctx){
    return check_and_block(ctx, AF_INET, get_l4_protocol_by_socket_type(ctx));
}

SEC("cgroup/sendmsg6")
int sendmsg6_filter(const struct bpf_sock_addr *ctx){
    return check_and_block(ctx, AF_INET6, get_l4_protocol_by_socket_type(ctx));
}

// ------------------------- SERVICE STAGE - NEW PROCESS AND EXIT PROCESS
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

char LICENSE[] SEC("license") = "GPL";