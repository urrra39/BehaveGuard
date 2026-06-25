# Contributing to BehaveGuard

Thanks for your interest in improving BehaveGuard. This guide explains how to
set up a development environment, what is expected before you submit changes,
and how to report security issues responsibly.

## Setup

1. **Fork** the repository on GitHub.
2. **Clone** your fork:
   ```bash
   git clone https://github.com/<your-username>/BehaveGuard.git
   cd BehaveGuard
   ```
3. **Install** the project with development dependencies:
   ```bash
   make dev
   ```
4. **Create a feature branch** off `develop`:
   ```bash
   git checkout -b feature/short-description
   ```

## Development Requirements

BehaveGuard instruments the Linux kernel via eBPF, so local development has
real constraints:

- **Linux kernel 5.15 or newer** — required for the eBPF features the collector
  relies on.
- **Python 3.10 or newer**.
- **Root privileges** — the integration tests load eBPF programs and therefore
  must run as root (e.g. `sudo make test-integration`). Unit tests do **not**
  require root and run anywhere.

## Before Submitting

Run the full local gate and make sure it is green:

```bash
make check
```

`make check` runs linting (`ruff`), type checking (`mypy`), and the test suite.
Pull requests that do not pass `make check` will not be merged.

## Pull Request Guidelines

- **One feature or fix per PR.** Keep changes focused and reviewable.
- **Include tests** for any new behavior or bug fix. New code paths should be
  covered by unit tests; kernel-facing behavior by integration tests.
- **Update the docs** whenever you add or change a CLI command or API endpoint.
- **Describe the change** clearly in the PR description: what it does, why it is
  needed, and any user-visible impact or migration notes.

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.** Please follow the
responsible disclosure process described in [SECURITY.md](SECURITY.md).
