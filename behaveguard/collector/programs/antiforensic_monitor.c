/*
 * antiforensic_monitor.c - BehaveGuard anti-forensics tracer (eBPF / BCC)
 *
 * Hooks : security_inode_unlink (kprobe)        - deleting files (log wiping)
 *         syscalls:sys_enter_utimensat          - timestomping (mtime/atime)
 *         syscalls:sys_enter_truncate           - truncating files (log zeroing)
 * Emits : struct antiforensic_event_t (296 bytes)
 *           -> ring buffer `antiforensic_events`
 *
 * Defense rationale: after a compromise, attackers cover their tracks by
 * destroying or doctoring evidence under /var/log: deleting auth.log/syslog
 * (unlink), zeroing them in place (truncate), and back-dating timestamps so
 * tampering blends in (utimensat = timestomping). We scope every hook tightly
 * to /var/log to keep the signal clean - routine application unlink/truncate
 * elsewhere on the system is ignored. The unlink path uses the LSM hook
 * (security_inode_unlink) so it fires regardless of which syscall (unlink,
 * unlinkat, rmdir paths) reached it, and we reconstruct "parent/name" from the
 * dentry to recover the basename and its directory.
 *
 * The 296-byte event (256-byte path) is far too large for the 512-byte BPF
 * stack once locals are accounted for, so it is assembled in a per-CPU scratch
 * map and emitted from there - the same pattern process_monitor.c uses.
 *
 * Identity convention: pid = pid_tgid >> 32, uid = low 32 of uid_gid,
 * timestamp = bpf_ktime_get_ns(), comm = bpf_get_current_comm().
 *
 * struct antiforensic_event_t MUST match AntiforensicEventRaw in
 * event_types.py (verified sizeof == 296, natural alignment, no packing).
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#ifndef OWN_PID
#define OWN_PID 0
#endif

#define AF_PATH_LEN 256

/* antiforensic_event_t.action values */
#define ACT_UNLINK    0   /* file deletion under /var/log              */
#define ACT_TIMESTOMP 1   /* utimensat() back-dating under /var/log    */
#define ACT_TRUNCATE  2   /* truncate() zeroing under /var/log         */

struct antiforensic_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 uid;
    u32 action;
    char comm[TASK_COMM_LEN];
    char path[AF_PATH_LEN];
};

BPF_RINGBUF_OUTPUT(antiforensic_events, 256);

/* Per-CPU scratch: the 296-byte event will not fit on the BPF stack. */
BPF_PERCPU_ARRAY(af_scratch, struct antiforensic_event_t, 1);

/*
 * Fixed 8-character prefix test for "/var/log". p is a kernel-resident buffer
 * (evt->path) that we have already populated, so the indexed reads are in
 * bounds. The literal length 8 is constant, so the loop fully unrolls. We
 * compare only the prefix, so "/var/log", "/var/log/auth.log", and
 * "/var/log/" all match while "/var/logger" technically also matches - that is
 * acceptable for a coarse scope filter and is refined by the ML layer.
 */
static __always_inline int __is_varlog(const char *p) {
    const char k[] = "/var/log";
    for (int i = 0; i < 8; i++) {
        if (p[i] != k[i])
            return 0;
    }
    return 1;
}

/*
 * Grab a zero-initialised scratch event and stamp the common identity fields.
 * Returns NULL only if the per-CPU lookup somehow fails (cannot happen for a
 * single-entry array, but the verifier requires the NULL check).
 */
static __always_inline struct antiforensic_event_t *af_evt_init(u32 tgid,
                                                                u32 action) {
    u32 zero = 0;
    struct antiforensic_event_t *evt = af_scratch.lookup(&zero);
    if (!evt)
        return NULL;
    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = tgid;
    evt->uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt->action = action;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    return evt;
}

/*
 * security_inode_unlink(dir, dentry) - LSM gate for every file deletion.
 * We reconstruct "<parent>/<name>" from the dentry and only emit when the
 * immediate parent directory is named "log" (i.e. the file lives in /var/log).
 * Scoping on the parent dentry name avoids walking the whole path (cheap and
 * verifier-friendly) while still catching the /var/log/* deletions we care
 * about.
 */
int kprobe__security_inode_unlink(struct pt_regs *ctx, struct inode *dir,
                                  struct dentry *dentry) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    /* Basename of the file being deleted. */
    struct qstr d_name = {};
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);

    /* Parent dentry, then its name (the containing directory). */
    struct dentry *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent);
    struct qstr p_name = {};
    if (parent)
        bpf_probe_read_kernel(&p_name, sizeof(p_name), &parent->d_name);

    /* Read the parent directory name into a small bounded buffer first so we
     * can test it cheaply before committing a scratch event. */
    char parent_buf[16] = {};
    if (p_name.name)
        bpf_probe_read_kernel_str(&parent_buf, sizeof(parent_buf),
                                  (void *)p_name.name);

    /* Only /var/log/* deletions are interesting: require parent dir == "log".
     * "log\0" is 4 bytes; compare exactly so "logrotate.d" does not match. */
    if (!(parent_buf[0] == 'l' && parent_buf[1] == 'o' &&
          parent_buf[2] == 'g' && parent_buf[3] == '\0'))
        return 0;

    struct antiforensic_event_t *evt = af_evt_init(tgid, ACT_UNLINK);
    if (!evt)
        return 0;

    /* Compose "parent/name" into evt->path. Bounded, verifier-friendly writes:
     * write the parent, append '/', then the basename. */
    int off = 0;
    int n = bpf_probe_read_kernel_str(&evt->path[0], AF_PATH_LEN,
                                      (void *)p_name.name);
    if (n > 0) {
        off = n - 1;                       /* drop the trailing NUL */
        if (off < 0 || off > AF_PATH_LEN - 2)
            off = 0;
        off &= (AF_PATH_LEN - 1);          /* keep the verifier happy */
        evt->path[off] = '/';
        off += 1;
    }
    if (off >= 0 && off <= AF_PATH_LEN - 1 && d_name.name) {
        off &= (AF_PATH_LEN - 1);
        bpf_probe_read_kernel_str(&evt->path[off], AF_PATH_LEN - off,
                                  (void *)d_name.name);
    }

    antiforensic_events.ringbuf_output(evt, sizeof(*evt), 0);
    return 0;
}

/*
 * utimensat(dirfd, filename, times, flags) - the modern timestamp-setting
 * syscall and the standard timestomping primitive. We read the user-supplied
 * filename and only emit when it targets /var/log.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_utimensat) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct antiforensic_event_t *evt = af_evt_init(tgid, ACT_TIMESTOMP);
    if (!evt)
        return 0;

    /* args->filename is a user pointer (const char __user *). */
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path),
                            (void *)args->filename);

    if (!__is_varlog(evt->path))
        return 0;   /* not a log timestomp - drop without emitting */

    antiforensic_events.ringbuf_output(evt, sizeof(*evt), 0);
    return 0;
}

/*
 * truncate(path, length) - zeroing a file in place (length 0 wipes a log while
 * keeping the inode/fd valid, a favourite for hiding from naive size checks).
 * Scoped to /var/log like the others.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_truncate) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (tgid == OWN_PID || tgid == 0)
        return 0;

    struct antiforensic_event_t *evt = af_evt_init(tgid, ACT_TRUNCATE);
    if (!evt)
        return 0;

    /* args->path is a user pointer (const char __user *). */
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path),
                            (void *)args->path);

    if (!__is_varlog(evt->path))
        return 0;   /* not a log truncate - drop without emitting */

    antiforensic_events.ringbuf_output(evt, sizeof(*evt), 0);
    return 0;
}
