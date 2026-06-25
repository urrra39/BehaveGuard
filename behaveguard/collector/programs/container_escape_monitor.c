/*
 * container_escape_monitor.c - BehaveGuard namespace-breakout tracer (eBPF/BCC)
 *
 * Hooks : syscalls:sys_enter_setns        - joining an existing namespace
 *         syscalls:sys_enter_unshare      - detaching into new namespaces
 *         syscalls:sys_enter_pivot_root   - swapping the root mount
 * Emits : struct container_escape_event_t (40 bytes)
 *           -> ring buffer `container_events`
 *
 * Defense rationale: container escapes almost always manipulate namespaces and
 * the mount tree. setns(fd, nstype) re-enters a namespace (e.g. the host PID/
 * net/mount ns leaked via a bind-mounted /proc fd) - the canonical "nsenter
 * into the host" break-out. unshare(flags) with CLONE_NEWUSER|CLONE_NEWNS is
 * the user-namespace privilege-escalation primitive (map root, then mount).
 * pivot_root() is the final step of many chroot/rootfs swaps used to pivot
 * onto the host filesystem. We record the raw flags so the scoring layer can
 * distinguish "joined a user+mount ns" from benign single-ns operations.
 *
 * Identity convention: pid = pid_tgid >> 32, uid = low 32 of uid_gid,
 * timestamp = bpf_ktime_get_ns(), comm = bpf_get_current_comm().
 *
 * struct container_escape_event_t MUST match ContainerEscapeEventRaw in
 * event_types.py (verified sizeof == 40, natural alignment, no packing).
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#ifndef OWN_PID
#define OWN_PID 0
#endif

/* container_escape_event_t.action values */
#define ACT_SETNS       0
#define ACT_UNSHARE     1
#define ACT_PIVOT_ROOT  2

struct container_escape_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 uid;
    u32 action;
    u32 flags;                 /* nstype / unshare flags; 0 for pivot_root */
    char comm[TASK_COMM_LEN];
};

BPF_RINGBUF_OUTPUT(container_events, 256);

/*
 * Common fill for the 40-byte event (fits on the BPF stack, no scratch map).
 * Zero-init guarantees deterministic padding for the ctypes mapping.
 */
static __always_inline void esc_evt_init(struct container_escape_event_t *evt,
                                         u32 tgid, u32 action, u32 flags) {
    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = tgid;
    evt->uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt->action = action;
    evt->flags = flags;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

/* setns(int fd, int nstype): nstype carries the CLONE_NEW* namespace mask. */
TRACEPOINT_PROBE(syscalls, sys_enter_setns) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct container_escape_event_t evt;
    esc_evt_init(&evt, tgid, ACT_SETNS, (u32)args->flags);

    container_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

/* unshare(int unshare_flags): the CLONE_NEW* bits requested for detachment. */
TRACEPOINT_PROBE(syscalls, sys_enter_unshare) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct container_escape_event_t evt;
    esc_evt_init(&evt, tgid, ACT_UNSHARE, (u32)args->unshare_flags);

    container_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

/*
 * pivot_root(new_root, put_old): no flags argument exists, so flags=0. The mere
 * occurrence inside a container context is the signal of interest.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_pivot_root) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct container_escape_event_t evt;
    esc_evt_init(&evt, tgid, ACT_PIVOT_ROOT, 0);

    container_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}
