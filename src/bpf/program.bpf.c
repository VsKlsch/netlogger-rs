// bpf/program.bpf.c
#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Family constants
#ifndef AF_INET
    #define AF_INET 2
    #define AF_INET6 10
#endif

#ifndef EPERM
    #define EPERM 1
#endif

// Base profile types
#define BASE_PROFILE_DENY_ALL 0
#define BASE_PROFILE_PASS_ALL 1

// Event status
#define EVENT_STATUS_BLOCK 0
#define EVENT_STATUS_PASS 1
#define EVENT_STATUS_UNKNOWN 2

// Cgroup filter result
#define CGROUP_FILTER_RESULT_BLOCK 0
#define CGROUP_FILTER_RESULT_PASS 1

// L3 protocol
#define L4_PROTOCOL_TCP 0
#define L4_PROTOCOL_UDP 1

// Parse Status
#define PARSE_STATUS_SUCCESS 0
#define PARSE_STATUS_ERROR_AT_READ_FAMILY 1
#define PARSE_STATUS_ERROR_AT_READ_SOCKADDR 2
#define PARSE_STATUS_PARTIAL 3


// Connect event for transfer into userspace
struct event{
    __u32 pid;
    __u32 tgid;
    __u32 syscall_id;
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct event);
} events_in_processing SEC(".maps");

volatile const __u32 initial_target_tgid = 0;
volatile const __u8 fallback_profile = BASE_PROFILE_DENY_ALL;

static __always_inline int parse_sockaddr(__u64 uservaddr, struct event *e){
    __u16 family;

    if(bpf_probe_read_user(&family, sizeof(family), (void*)uservaddr)){
        return PARSE_STATUS_ERROR_AT_READ_FAMILY;
    }

    e->family = family;

    __builtin_memset(e->ip, 0, sizeof(e->ip));

    if(family == AF_INET){
        if(bpf_probe_read_user(&e->port, sizeof(e->port), (void*)(uservaddr+offsetof(struct sockaddr_in, sin_port)))){
            return PARSE_STATUS_ERROR_AT_READ_SOCKADDR;
        }
        
        if(bpf_probe_read_user(&e->ip[12], 4, (void*)(uservaddr+offsetof(struct sockaddr_in, sin_addr)))){
            return PARSE_STATUS_ERROR_AT_READ_SOCKADDR;
        }

        // IPv6 mapped IPv4 addr
        e->ip[10] = 0xff;
        e->ip[11] = 0xff;
    }else if (family == AF_INET6){
        if(bpf_probe_read_user(&e->port, sizeof(e->port), (void*)(uservaddr+offsetof(struct sockaddr_in6, sin6_port)))){
            return PARSE_STATUS_ERROR_AT_READ_SOCKADDR;
        }
        if(bpf_probe_read_user(e->ip, 16, (void*)(uservaddr+offsetof(struct sockaddr_in6, sin6_addr)))){
            return PARSE_STATUS_ERROR_AT_READ_SOCKADDR;
        }
    }
    return PARSE_STATUS_SUCCESS;
}

static __always_inline void ip4_into_ipv6mapped(__u32 ipv4_addr, __u8 ipv6_mapped_addr[16]) {
    __builtin_memset(ipv6_mapped_addr, 0, 16);
    ipv6_mapped_addr[10] = 0xff;
    ipv6_mapped_addr[11] = 0xff;
    __builtin_memcpy(&ipv6_mapped_addr[12], &ipv4_addr, 4);
}

static __always_inline int check_and_block(const struct bpf_sock_addr *ctx, __u8 family) {
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    bool in_map = bpf_map_lookup_elem(&tracing_tgids, &tgid) != NULL;
    bool is_init = (initial_target_tgid != 0) && (tgid == initial_target_tgid);

    if (!in_map && !is_init){
        return CGROUP_FILTER_RESULT_PASS;
    }

    __u8 ipv6_mapped_addr[16];
    if(family == AF_INET){
        ip4_into_ipv6mapped(ctx->user_ip4, ipv6_mapped_addr);
    }else if (family == AF_INET6){
        bpf_probe_read_kernel(ipv6_mapped_addr, sizeof(ipv6_mapped_addr), ctx->user_ip6);
    }else{
        return CGROUP_FILTER_RESULT_BLOCK;
    }

    bool is_in_list = false;
    if(bpf_map_lookup_elem(&ip_list, ipv6_mapped_addr) != NULL){
        is_in_list = true;
    }

    const __u32 key = 0;

    __u8 *profile_ptr = (__u8*)bpf_map_lookup_elem(&profile_mode, &key);
    __u8 profile = profile_ptr == NULL ? fallback_profile : *profile_ptr;

    bool block = (profile == BASE_PROFILE_PASS_ALL) ? is_in_list : !is_in_list;

    return block ? CGROUP_FILTER_RESULT_BLOCK : CGROUP_FILTER_RESULT_PASS;
}

static __always_inline bool is_our_process(__u64 pid_tgid){
    __u32 tgid = (__u32)(pid_tgid >> 32);

    bool in_map = bpf_map_lookup_elem(&tracing_tgids, &tgid) != NULL;
    bool is_initial = (initial_target_tgid != 0) && (tgid == initial_target_tgid);

    return in_map || is_initial;
}

static __always_inline void fill_event_struct(struct event *e, __u64 pid_tgid, __u8 l4_protocol){
    __u32 tgid = (__u32)(pid_tgid >> 32);

    e->pid = (__u32)(pid_tgid);
    e->tgid = tgid;
    e->syscall_id = 1;
    e->timestamp = bpf_ktime_get_ns();
    e->l4_protocol = l4_protocol;
    e->event_status = EVENT_STATUS_UNKNOWN;
    e->parse_status = PARSE_STATUS_PARTIAL;
}

static __always_inline void first_stage(__u64 uservaddr, __u8 l3_protocol){
    if(uservaddr == 0){
        return;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if(!is_our_process(pid_tgid)){
        return;
    }

    struct event e;
    fill_event_struct(&e, pid_tgid, l3_protocol);

    // Submit packet info if at least family field filled;
    e.parse_status = parse_sockaddr(uservaddr, &e);

    if(bpf_map_update_elem(&events_in_processing, &pid_tgid, &e, BPF_ANY)){
        bpf_printk("[Lost event] Error when try to update event to HashMap.");
    }
}

static __always_inline void third_stage(int verdict) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct event *e = bpf_map_lookup_elem(&events_in_processing, &pid_tgid);
    if(e == NULL) {
        return;
    }

    e->event_status = (verdict == -EPERM) ? EVENT_STATUS_BLOCK : EVENT_STATUS_PASS;

    struct event *event_in_ringbuf;
    event_in_ringbuf = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(event_in_ringbuf){
        __builtin_memcpy(event_in_ringbuf, e, sizeof(struct event));
        bpf_ringbuf_submit(event_in_ringbuf, 0);
        bpf_map_delete_elem(&events_in_processing, &pid_tgid);
    }else{
        bpf_printk("[Lost event] Error when try to load event to ringbuf.");
    }
}

// ------------------ FIRST STAGE - SYS ENTER -----------------------------

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx){
    first_stage(ctx->args[1], L4_PROTOCOL_TCP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto_enter(struct trace_event_raw_sys_enter *ctx){
    first_stage(ctx->args[4], L4_PROTOCOL_UDP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg_enter(struct trace_event_raw_sys_enter *ctx){
    struct user_msghdr msg;
    if(bpf_probe_read_user(&msg, sizeof(msg), (void*)ctx->args[1])){
        return 0;
    }
    first_stage((__u64)msg.msg_name, L4_PROTOCOL_UDP);
    return 0;
}

// ------------------ SECOND STAGE - FILTER AND BLOCK AT CGROUP------------

SEC("cgroup/connect4")
int connect4_filter(const struct bpf_sock_addr *ctx){
    return check_and_block(ctx, AF_INET);
}

SEC("cgroup/connect6")
int connect6_filter(const struct bpf_sock_addr *ctx){
    return check_and_block(ctx, AF_INET6);
}

SEC("cgroup/sendmsg4")
int sendmsg4_filter(const struct bpf_sock_addr *ctx){
    return check_and_block(ctx, AF_INET);
}

SEC("cgroup/sendmsg6")
int sendmsg6_filter(const struct bpf_sock_addr *ctx){
    return check_and_block(ctx, AF_INET6);
}

// ------------------------- THIRD STAGE - SYS EXIT --------------------------

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx){
    third_stage(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_sendto_exit(struct trace_event_raw_sys_exit *ctx){
    third_stage(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int trace_sendmsg_exit(struct trace_event_raw_sys_exit *ctx){
    third_stage(ctx->ret);
    return 0;
}

// ------------------------- SERVICE CTAGE - NEW PROCESS AND EXIT PROCESS
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