/*
 * injection_monitor.c - BehaveGuard process-injection tracer (eBPF / BCC)
 *
 * Hooks : security_ptrace_access_check (kprobe) - PTRACE_ATTACH access checks
 *         syscalls:sys_enter_process_vm_writev   - cross-process memory writes
 *         mem_write                  (kprobe)    - writes to /proc/<pid>/mem
 * Emits : struct injection_event_t (40 bytes) -> ring buffer `injection_events`
 *
 * Defense rationale: process injection is one process hijacking the address
 * space of another to run code under a trusted identity (classic ptrace
 * shellcode injection, process_vm_writev() implant delivery, and the
 * /proc/<pid>/mem write trick used to bypass anti-debug). Each technique
 * touches a distinct kernel path, so we instrument all three and tag the
 * `method` field so the ML/scoring layer can weight them. The LSM hook
 * security_ptrace_access_check fires for *every* attach attempt regardless of
 * the entry syscall (ptrace, /proc access, etc.), which is why it is the most
 * reliable signal of the three.
 *
 * Identity convention (shared across BehaveGuard probes): pid stored is the
 * userspace PID (pid_tgid >> 32), uid is the low 32 bits of uid_gid, timestamp
 * is bpf_ktime_get_ns(). target_pid is the *victim* process being written to.
 *
 * struct injection_event_t MUST match InjectionEventRaw in event_types.py
 * (verified sizeof == 40, natural alignment, no packing).
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#ifndef OWN_PID
#define OWN_PID 0
#endif

/*
 * PTRACE_MODE_ATTACH bit from include/linux/ptrace.h. We hardcode the bit
 * value rather than rely on the kernel header being in scope for the BCC
 * preprocessor; 0x02 has been stable across the 4.x/5.x/6.x ABI. We only care
 * about ATTACH-class accesses (write/inject capable) and deliberately ignore
 * the far noisier READ-class checks (0x04) that fire on benign introspection.
 */
#ifndef PTRACE_MODE_ATTACH
#define PTRACE_MODE_ATTACH 0x02
#endif

/* injection_event_t.method values */
#define METHOD_PTRACE      0   /* ptrace(PTRACE_ATTACH/POKE...) path           */
#define METHOD_PROC_MEM    1   /* write() to /proc/<pid>/mem                   */
#define METHOD_VM_WRITEV   2   /* process_vm_writev() cross-process write      */

struct injection_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 uid;
    u32 target_pid;            /* victim process being injected into           */
    u32 method;
    char comm[TASK_COMM_LEN];
};

BPF_RINGBUF_OUTPUT(injection_events, 256);

/*
 * Fill the identity fields common to every injection event. The 40-byte event
 * fits comfortably on the BPF stack, so no per-CPU scratch map is needed here.
 * Always zero-initialise so the trailing padding bytes are deterministic and
 * the ctypes struct on the Python side reads clean.
 */
static __always_inline void inj_evt_init(struct injection_event_t *evt,
                                         u32 tgid, u32 method) {
    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = tgid;
    evt->uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt->method = method;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

/*
 * security_ptrace_access_check(child, mode) - the LSM gate every ptrace attach
 * funnels through. `child` is the target task; `mode` carries the
 * PTRACE_MODE_* flags. We only emit for ATTACH-class (write-capable) checks.
 */
int kprobe__security_ptrace_access_check(struct pt_regs *ctx,
                                         struct task_struct *child,
                                         unsigned int mode) {
    /* Ignore read-only introspection; only attach/inject attempts matter. */
    if (!(mode & PTRACE_MODE_ATTACH))
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct injection_event_t evt;
    inj_evt_init(&evt, tgid, METHOD_PTRACE);

    /* Resolve the victim's thread-group id from the target task_struct. */
    u32 target = 0;
    bpf_probe_read_kernel(&target, sizeof(target), &child->tgid);
    evt.target_pid = target;

    injection_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

/*
 * process_vm_writev(pid, ...) writes directly into another process's memory.
 * The first syscall argument is the victim PID, available verbatim from the
 * tracepoint args, so the victim is known precisely at this hook.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_process_vm_writev) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct injection_event_t evt;
    inj_evt_init(&evt, tgid, METHOD_VM_WRITEV);
    evt.target_pid = (u32)args->pid;   /* victim PID from syscall arg 0 */

    injection_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

/*
 * mem_write() is the kernel file-op backing write() on /proc/<pid>/mem.
 * Reaching it means someone is writing into a process's memory via procfs.
 * The victim PID is encoded in the path component, which is not available at
 * this function boundary; target_pid is left 0 and the victim is resolved by
 * userspace (correlating the writer's open fd -> /proc/<pid>/mem) or by the
 * ptrace/vm_writev signals that typically accompany the same campaign.
 */
int kprobe__mem_write(struct pt_regs *ctx, struct file *file,
                      const char __user *buf, size_t count, loff_t *ppos) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct injection_event_t evt;
    inj_evt_init(&evt, tgid, METHOD_PROC_MEM);
    evt.target_pid = 0;   /* unknown at this hook; resolved out-of-band */

    injection_events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}
