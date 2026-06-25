/*
 * lolbin_monitor.c - BehaveGuard living-off-the-land binary tracer (eBPF/BCC)
 *
 * Hooks : sched:sched_process_exec - fires after a successful exec, with comm
 *                                     already set to the new binary name
 * Emits : struct lolbin_event_t (40 bytes) -> ring buffer `lolbin_events`
 *
 * Defense rationale: "LOLBins" are legitimate, pre-installed tools that
 * attackers abuse instead of dropping their own malware - download cradles
 * (wget/curl), interpreters (python/perl/bash), bind/reverse-shell helpers
 * (nc/ncat/socat), encoders that hide payloads (base64/xxd), raw copiers (dd),
 * persistence (crontab/at/systemctl), and permission flips (chmod). Watching
 * exec for an exact-match against this curated watchlist gives a cheap,
 * high-signal feed; the ML layer then uses the parent (ppid) and surrounding
 * process tree to separate "an admin ran systemctl" from "the web server
 * spawned bash spawned curl".
 *
 * We emit ONLY on a watchlist hit to keep the ring buffer quiet - the generic
 * process_monitor.c already records every exec, so this probe is purely the
 * fast-path LOLBin classifier.
 *
 * Identity convention: pid = pid_tgid >> 32, uid = low 32 of uid_gid,
 * timestamp = bpf_ktime_get_ns(), comm = bpf_get_current_comm() (the new image).
 *
 * struct lolbin_event_t MUST match LolbinEventRaw in event_types.py
 * (verified sizeof == 40, natural alignment, no packing).
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#ifndef OWN_PID
#define OWN_PID 0
#endif

struct lolbin_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
};

BPF_RINGBUF_OUTPUT(lolbin_events, 256);

/*
 * Compile-time-bounded string equality against a literal. `n` is always
 * sizeof(literal)-1 (a constant), so the verifier fully unrolls the loop with
 * no back-edge. We also require c[n] == '\0' so that "curlx" does not match
 * "curl" - the watchlist demands exact basenames, not prefixes. comm is a
 * fixed 16-byte buffer (TASK_COMM_LEN), so reads stay in-bounds for any n < 16.
 */
static __always_inline int __streq(const char *c, const char *lit, int n) {
    for (int i = 0; i < n; i++) {
        if (c[i] != lit[i])
            return 0;
    }
    return c[n] == '\0';
}

/* EQ(comm, "curl") -> exact-match test with a compile-time length. */
#define EQ(c, s) __streq((c), (s), sizeof(s) - 1)

/* real_parent->tgid of the current task (the userspace PID of the parent). */
static __always_inline u32 current_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    u32 ppid = 0;
    if (parent)
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
    return ppid;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    /* Grab the just-exec'd image name straight from the task comm. */
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    /*
     * Exact-match against the LOLBin watchlist. Each EQ() expands to a fully
     * unrolled, constant-bounded comparison, so the whole chain is verifier
     * friendly. Bail out early for the common (non-LOLBin) case.
     */
    int hit = EQ(comm, "wget")     || EQ(comm, "curl")    ||
              EQ(comm, "python")   || EQ(comm, "python3") ||
              EQ(comm, "perl")     || EQ(comm, "bash")    ||
              EQ(comm, "nc")       || EQ(comm, "ncat")    ||
              EQ(comm, "socat")    || EQ(comm, "base64")  ||
              EQ(comm, "xxd")      || EQ(comm, "dd")      ||
              EQ(comm, "crontab")  || EQ(comm, "at")      ||
              EQ(comm, "systemctl")|| EQ(comm, "chmod");
    if (!hit)
        return 0;

    struct lolbin_event_t evt;
    __builtin_memset(&evt, 0, sizeof(evt));
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = tgid;
    evt.ppid = current_ppid();
    evt.uid = bpf_get_current_uid_gid() & 0xffffffff;
    __builtin_memcpy(&evt.comm, comm, sizeof(evt.comm));

    lolbin_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}
