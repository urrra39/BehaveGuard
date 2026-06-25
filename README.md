# BehaveGuard 🛡️

> Runtime behavioral anomaly detection for Linux — powered by eBPF and Machine Learning.

**Status:** 🚧 Under active development

BehaveGuard monitors every Linux process via eBPF and uses an LSTM + VAE ensemble
to detect when a process starts behaving abnormally — catching zero-day malware that
signature-based tools completely miss.

## How it works

1. **eBPF probes** capture syscalls, file access, network connections, and process
   spawning in real time, with low overhead, straight from kernel space.
2. **ML models** learn what "normal" looks like *per process type* during a training
   phase (an LSTM sequence model plus a variational autoencoder).
3. **Any deviation** from the learned baseline triggers a real-time, context-rich
   alert that explains *why* the behavior was flagged.

### Why behavioral detection?

Traditional antivirus asks *"does this code match known malware?"* — and misses
anything it has never seen. BehaveGuard asks *"is this process doing things it
normally does?"*. A Python web server that suddenly reads `/etc/shadow`, connects to
a foreign IP on port 4444, and spawns a shell is compromised — even if the malware is
brand new.

## Quick Start *(coming soon)*

```bash
pip install behaveguard
sudo behaveguard init
sudo behaveguard train --duration 60
sudo behaveguard run
```

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for full design details.

## License

MIT © urrra39
