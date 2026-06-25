/*
 * syscall_monitor.c - BehaveGuard syscall tracer (eBPF / BCC)
 *
 * Hooks : raw_syscalls:sys_enter  +  raw_syscalls:sys_exit
 * Emits : struct syscall_event_t (80 bytes) -> ring buffer `syscall_events`
 *
 * Every syscall is captured at entry (number + first three arguments) and
 * completed at exit (return value), so the return code travels with the call
 * that produced it. The first three arguments are kept because they carry the
 * security-relevant payload for the sensitive calls BehaveGuard scores on
 * (setuid/setgid uid, ptrace request, execve target, kill signal/target).
 *
 * Defense / anti-tamper: the Python loader compiles this with
 *   -DOWN_PID=<collector_pid>
 * so the detector never observes (and never feeds back on) itself. The idle /
 * kernel task (tgid 0) is also skipped.
 *
 * The C struct below MUST stay byte-for-byte identical to SyscallEventRaw in
 * behaveguard/collector/event_types.py (verified sizeof == 80, natural
 * alignment, no packing).
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#ifndef OWN_PID
#define OWN_PID 0
#endif

struct syscall_event_t {
    u64 timestamp_ns;
    u32 pid;                  /* thread id  (kernel "pid") */
    u32 tgid;                 /* process id (userspace PID) */
    u32 uid;
    char comm[TASK_COMM_LEN]; /* TASK_COMM_LEN == 16 */
    u64 syscall_nr;
    u64 ret;
    u64 args[3];
};

BPF_RINGBUF_OUTPUT(syscall_events, 256);

/* Per-task scratch so the return value captured at sys_exit can be stitched
 * onto the call recorded at sys_enter. Keyed by the full pid_tgid. */
BPF_HASH(active_syscall, u64, struct syscall_event_t);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id & 0xffffffff;

    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct syscall_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.tgid = tgid;
    evt.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.syscall_nr = args->id;
    evt.args[0] = args->args[0];
    evt.args[1] = args->args[1];
    evt.args[2] = args->args[2];
    evt.ret = 0;

    active_syscall.update(&id, &evt);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 id = bpf_get_current_pid_tgid();

    struct syscall_event_t *evt = active_syscall.lookup(&id);
    if (!evt)
        return 0;

    evt->ret = (u64)args->ret;
    syscall_events.ringbuf_output(evt, sizeof(*evt), 0);
    active_syscall.delete(&id);
    return 0;
}
