/*
 * file_monitor.c - BehaveGuard file-access tracer (eBPF / BCC)
 *
 * Hooks : vfs_open                 - file opens (+ open flags)
 *         vfs_read                 - reads (+ byte count)
 *         vfs_write                - writes (+ byte count)
 *         security_inode_unlink    - deletions (LSM hook)
 * Emits : struct file_event_t (312 bytes) -> ring buffer `file_events`
 *
 * Defense rationale: reads of /etc/shadow, /root/.ssh, /proc/<pid>/mem are the
 * fingerprint of credential dumping; writes into system dirs and unlinks are
 * tamper/anti-forensics signals. The unlink hook is the LSM `security_inode_*`
 * entry rather than `vfs_unlink` on purpose - the LSM signature
 * (inode *dir, dentry *) is stable across kernel versions, whereas vfs_unlink's
 * argument list changed (idmap/user_namespace) between 5.12 / 6.3.
 *
 * The 312-byte event is too large for the 512-byte BPF stack once locals are
 * added, so it is built in a per-CPU scratch map. Path capture is best-effort:
 * the dentry basename is recorded here; full absolute-path reconstruction is
 * done in user space from the process cwd / fd table (kernel-side full-path
 * walking is unbounded and verifier-hostile).
 *
 * struct file_event_t MUST match FileEventRaw in event_types.py
 * (verified sizeof == 312).
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>

#ifndef OWN_PID
#define OWN_PID 0
#endif

#define PATH_MAX_LEN 256

/* file_event_t.operation values */
#define OP_OPEN   0
#define OP_READ   1
#define OP_WRITE  2
#define OP_UNLINK 3

struct file_event_t {
    u64 timestamp_ns;
    s64 ret;
    u32 pid;
    u32 uid;
    u32 flags;
    u32 bytes_count;
    u32 operation;
    char comm[TASK_COMM_LEN];
    char path[PATH_MAX_LEN];
};

BPF_RINGBUF_OUTPUT(file_events, 256);
BPF_PERCPU_ARRAY(file_scratch, struct file_event_t, 1);

/* Grab a zeroed scratch event pre-filled with the common identity fields, or
 * NULL if this task should be skipped. */
static __always_inline struct file_event_t *file_evt_init(u32 op) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return NULL;

    u32 zero = 0;
    struct file_event_t *evt = file_scratch.lookup(&zero);
    if (!evt)
        return NULL;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = tgid;
    evt->uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt->operation = op;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    return evt;
}

/* Copy the dentry basename into evt->path. */
static __always_inline void read_dentry_name(struct file_event_t *evt, struct dentry *dentry) {
    if (!dentry)
        return;
    const unsigned char *name = NULL;
    bpf_probe_read_kernel(&name, sizeof(name), &dentry->d_name.name);
    if (name)
        bpf_probe_read_kernel_str(&evt->path, sizeof(evt->path), name);
}

int kprobe__vfs_open(struct pt_regs *ctx, const struct path *path, struct file *file) {
    struct file_event_t *evt = file_evt_init(OP_OPEN);
    if (!evt)
        return 0;

    struct dentry *dentry = NULL;
    if (path)
        bpf_probe_read_kernel(&dentry, sizeof(dentry), &path->dentry);
    read_dentry_name(evt, dentry);

    unsigned int f_flags = 0;
    if (file)
        bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &file->f_flags);
    evt->flags = f_flags;
    evt->ret = 0;

    file_events.ringbuf_output(evt, sizeof(*evt), 0);
    return 0;
}

int kprobe__vfs_read(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    struct file_event_t *evt = file_evt_init(OP_READ);
    if (!evt)
        return 0;

    struct dentry *dentry = NULL;
    if (file)
        bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
    read_dentry_name(evt, dentry);

    evt->bytes_count = (u32)count;
    evt->ret = 0;

    file_events.ringbuf_output(evt, sizeof(*evt), 0);
    return 0;
}

int kprobe__vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count) {
    struct file_event_t *evt = file_evt_init(OP_WRITE);
    if (!evt)
        return 0;

    struct dentry *dentry = NULL;
    if (file)
        bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
    read_dentry_name(evt, dentry);

    evt->bytes_count = (u32)count;
    evt->ret = 0;

    file_events.ringbuf_output(evt, sizeof(*evt), 0);
    return 0;
}

/* LSM hook: stable (inode *dir, dentry *) signature across kernel versions. */
int kprobe__security_inode_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry) {
    struct file_event_t *evt = file_evt_init(OP_UNLINK);
    if (!evt)
        return 0;

    read_dentry_name(evt, dentry);
    evt->ret = 0;

    file_events.ringbuf_output(evt, sizeof(*evt), 0);
    return 0;
}
