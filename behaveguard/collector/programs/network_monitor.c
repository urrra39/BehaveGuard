/*
 * network_monitor.c - BehaveGuard network tracer (eBPF / BCC)
 *
 * Hooks : tcp_v4_connect      (kprobe + kretprobe) - outbound TCP
 *         udp_sendmsg         (kprobe)             - UDP datagrams
 *         inet_csk_accept     (kretprobe)          - inbound TCP accept
 * Emits : struct network_event_t (56 bytes) -> ring buffer `network_events`
 *
 * Defense rationale: outbound connects catch C2 beacons / exfil; UDP catches
 * DNS-tunnelling and UDP beacons; the inbound accept hook is the piece most
 * behavioral tools omit - it is what flags a process that has started
 * *listening* and accepting shells (reverse/bind-shell, lateral movement).
 *
 * Address encoding: saddr/daddr are stored as the raw __be32 (network order);
 * user space converts to dotted-decimal. Ports are normalised to HOST order in
 * kernel (skc_num is already host order; skc_dport is __be16 and byte-swapped
 * here) so the Python side needs no further conversion.
 *
 * struct network_event_t MUST match NetworkEventRaw in event_types.py
 * (verified sizeof == 56).
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <uapi/linux/in.h>

#ifndef OWN_PID
#define OWN_PID 0
#endif

struct network_event_t {
    u64 timestamp_ns;
    u32 pid;                  /* userspace PID */
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 saddr;                /* __be32, network order (raw) */
    u32 daddr;                /* __be32, network order (raw) */
    u16 sport;                /* host order */
    u16 dport;                /* host order */
    u8 protocol;              /* 6 = TCP, 17 = UDP */
    u8 direction;             /* 0 = outbound, 1 = inbound */
    u32 bytes_count;
};

BPF_RINGBUF_OUTPUT(network_events, 256);

/* Stash the sock* between tcp_v4_connect entry and return. */
BPF_HASH(connectsock, u64, struct sock *);

static __always_inline u16 be16_to_host(u16 v) {
    return (u16)((v >> 8) | (v << 8));
}

/* Populate the common identity fields shared by every network event. */
static __always_inline void fill_sock(struct network_event_t *evt, struct sock *sk) {
    evt->saddr = sk->__sk_common.skc_rcv_saddr;
    evt->daddr = sk->__sk_common.skc_daddr;
    evt->sport = sk->__sk_common.skc_num;                 /* host order */
    evt->dport = be16_to_host(sk->__sk_common.skc_dport); /* __be16 -> host */
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;
    connectsock.update(&id, &sk);
    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct sock **skpp = connectsock.lookup(&id);
    if (!skpp)
        return 0;
    connectsock.delete(&id);

    if (PT_REGS_RC(ctx) != 0)   /* connect() failed to initiate */
        return 0;

    struct sock *sk = *skpp;
    struct network_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = id >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    fill_sock(&evt, sk);
    evt.protocol = IPPROTO_TCP;
    evt.direction = 0;          /* outbound */
    evt.bytes_count = 0;

    network_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct network_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = tgid;
    evt.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    fill_sock(&evt, sk);
    evt.protocol = IPPROTO_UDP;
    evt.direction = 0;          /* outbound */
    evt.bytes_count = (u32)len;

    network_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

/* inet_csk_accept returns the newly accepted child sock; a non-NULL return
 * means this process just accepted an inbound connection. */
int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (sk == NULL)
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct network_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = tgid;
    evt.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    fill_sock(&evt, sk);        /* daddr/dport = the remote peer that connected in */
    evt.protocol = IPPROTO_TCP;
    evt.direction = 1;          /* inbound */
    evt.bytes_count = 0;

    network_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}
