# Security Policy

BehaveGuard is a defensive security tool that loads eBPF programs into the Linux
kernel. Because of the privilege it requires, we take its own security posture
seriously and ask that you do too.

## Supported Versions

Only the **latest release** receives security updates. Please upgrade before
reporting an issue to confirm it still reproduces on the current version.

| Version        | Supported          |
| -------------- | ------------------ |
| Latest release | :white_check_mark: |
| Older releases | :x:                |

## Reporting a Vulnerability

Please use **GitHub private vulnerability reporting** (the "Report a
vulnerability" button under the repository's *Security* tab). Do **not** open a
public issue.

Include as much of the following as you can:

- A clear **description** of the vulnerability.
- **Reproduction** steps (proof-of-concept welcome).
- The **impact** — what an attacker could achieve.
- Any **suggested fix** or mitigation.

**Our commitment:**

- **48 hours** — initial response acknowledging your report.
- **7 days** — target patch turnaround for **critical** severity issues.

We will keep you informed throughout and credit you in the release notes unless
you prefer to remain anonymous.

## Security Design Notes

BehaveGuard is built to minimize its own attack surface and to never become an
exfiltration or tampering vector:

- **Root is required** to load eBPF programs. This is inherent to kernel
  instrumentation; run BehaveGuard only on systems where that trust is
  acceptable.
- **eBPF programs are read-only.** They *observe* kernel activity and never
  modify kernel state. All programs pass the in-kernel **eBPF verifier**, which
  enforces memory safety and bounded execution before they are allowed to load.
- **No process data leaves the machine** without explicit webhook configuration.
  With no webhook configured, all analysis stays local.
- **Webhook payloads are minimal.** They carry only an event **summary and
  anomaly score** — never raw event data, command lines, or captured process
  contents.
- **API authentication** uses a **locally-generated Bearer token**. The API is
  rate limited to **100 requests/minute** to blunt brute-force and abuse.
- **Self-filtering collector.** The collector excludes its own PID (`OWN_PID`)
  from collection, so it cannot observe or be driven by its own activity. This
  resists feedback loops and tampering aimed at the monitor itself.
