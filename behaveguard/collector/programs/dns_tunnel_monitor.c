/*
 * dns_tunnel_monitor.c - BehaveGuard DNS-tunnelling tracer (eBPF / BCC)
 *
 * Hooks : udp_sendmsg (kprobe) - outbound UDP datagrams
 * Emits : struct dns_tunnel_event_t (48 bytes)
 *           -> ring buffer `dns_tunnel_events`
 *
 * Defense rationale: DNS tunnelling smuggles command-and-control traffic and
 * exfiltrated data inside DNS queries to port 53, bypassing firewalls that
 * trust DNS. Benign queries are small; tunnelling tools (iodine, dnscat2, etc.)
 * pack long encoded labels, so a UDP datagram to :53 with a payload over ~100
 * bytes is a strong tunnelling indicator. We compute the destination from the
 * sendmsg arguments and emit ONLY on (dport == 53 && len > 100) to keep the
 * feed tight; the ML layer then looks at query rate/entropy on top of this.
 *
 * Destination resolution: connected UDP sockets carry the peer in the sock,
 * but unconnected sendto()-style sends pass it via msg->msg_name. We prefer
 * msg_name when present (a struct sockaddr_in *) and fall back to the sock's
 * __sk_common fields otherwise.
 *
 * Address encoding: daddr is the raw __be32 (network order); userspace renders
 * dotted-decimal. dport is normalised to HOST order and stored in a u32 field
 * so no further byte-swapping is needed on the Python side.
 *
 * struct dns_tunnel_event_t MUST match DnsTunnelEventRaw in event_types.py
 * (verified sizeof == 48, natural alignment, no packing).
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <uapi/linux/in.h>

#ifndef OWN_PID
#define OWN_PID 0
#endif

#define DNS_PORT        53
#define DNS_TUNNEL_MIN  100   /* payload bytes above which we flag tunnelling */

struct dns_tunnel_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 uid;
    u32 daddr;                 /* __be32, network order (raw) */
    u32 payload_size;          /* UDP send length in bytes    */
    u32 dport;                 /* host order                  */
    char comm[TASK_COMM_LEN];
};

BPF_RINGBUF_OUTPUT(dns_tunnel_events, 256);

/* Manual __be16 -> host byte swap (network ports are big-endian). */
static __always_inline u16 be16_to_host(u16 v) {
    return (u16)((v >> 8) | (v << 8));
}

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t len) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    u32 daddr = 0;
    u16 dport = 0;

    /*
     * Prefer the explicit destination from msg->msg_name (sendto / unconnected
     * sockets). msg_name is a void* into user-or-kernel sockaddr storage that
     * the kernel has already validated for this call path, so a kernel read is
     * safe here. If it is NULL the socket is connected and we read the peer
     * from the sock's common fields instead.
     */
    void *msg_name = NULL;
    bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);

    if (msg_name) {
        struct sockaddr_in sin = {};
        bpf_probe_read_kernel(&sin, sizeof(sin), msg_name);
        dport = be16_to_host(sin.sin_port);   /* __be16 -> host */
        daddr = sin.sin_addr.s_addr;           /* raw __be32     */
    } else {
        /* Connected socket: pull the peer from __sk_common. */
        dport = be16_to_host(sk->__sk_common.skc_dport); /* __be16 -> host */
        daddr = sk->__sk_common.skc_daddr;               /* raw __be32     */
    }

    /* Only large datagrams to the DNS port are of interest. */
    if (!(dport == DNS_PORT && len > DNS_TUNNEL_MIN))
        return 0;

    struct dns_tunnel_event_t evt;
    __builtin_memset(&evt, 0, sizeof(evt));
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = tgid;
    evt.uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt.daddr = daddr;                 /* network order, raw */
    evt.payload_size = (u32)len;
    evt.dport = (u32)dport;            /* host order */
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    dns_tunnel_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}
