"""BehaveGuard command-line interface (``behaveguard`` / ``python -m behaveguard``).

Commands: init, train, run, status, alerts, explain, whitelist. Heavy
dependencies (torch, BCC, FastAPI/uvicorn, Dash, pydantic settings) are imported
lazily inside the commands that need them, so ``--help`` and the lightweight
commands work without the full stack installed.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import re
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import click

BG_HOME = Path.home() / ".behaveguard"
SAFE_PIDS_FILE = BG_HOME / "safe_pids.json"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _load_settings():
    from behaveguard.config.settings import get_settings

    return get_settings()


def _parse_duration(text: str) -> timedelta:
    """Parse a duration like ``90s``/``15m``/``1h``/``7d`` into a timedelta."""
    match = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", text.lower())
    if not match:
        raise click.BadParameter(f"invalid duration {text!r}; use e.g. 30m, 1h, 7d")
    value, unit = int(match.group(1)), match.group(2)
    return timedelta(seconds=value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit])


def _kernel_supports_ebpf() -> bool:
    """Best-effort check that the kernel is >= 5.15."""
    release = platform.release()
    match = re.match(r"(\d+)\.(\d+)", release)
    if not match:
        return False
    major, minor = int(match.group(1)), int(match.group(2))
    return (major, minor) >= (5, 15)


# --------------------------------------------------------------------------- #
# CLI group
# --------------------------------------------------------------------------- #
@click.group()
@click.version_option(package_name="behaveguard", message="BehaveGuard %(version)s")
def cli() -> None:
    """BehaveGuard — runtime behavioral anomaly detection for Linux."""


@cli.command()
def init() -> None:
    """Initialize BehaveGuard: check eBPF support, set up storage, mint an API key."""
    click.echo("Initializing BehaveGuard…\n")

    if _kernel_supports_ebpf():
        click.echo(f"  [ok] eBPF support: kernel {platform.release()} — supported")
    else:
        click.echo(f"  [!!] kernel {platform.release()} may not support eBPF (need 5.15+)")

    try:
        import bcc  # noqa: F401

        click.echo("  [ok] BCC installed")
    except ImportError:
        click.echo("  [!!] BCC not installed (run scripts/install_deps.sh on Linux)")

    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        click.echo("  [!!] not running as root — eBPF load will require sudo")

    settings = _load_settings()
    BG_HOME.mkdir(parents=True, exist_ok=True)

    async def _init_stores() -> None:
        from behaveguard.storage.alert_store import AlertStore
        from behaveguard.storage.event_store import EventStore

        await EventStore(settings).initialize()
        await AlertStore(settings).initialize()

    asyncio.run(_init_stores())
    click.echo(f"  [ok] Storage initialized: {Path(settings.storage.sqlite_path).parent}")

    token = os.environ.get("BEHAVEGUARD_API_TOKEN") or secrets.token_hex(16)
    (BG_HOME / "api_token").write_text(token, encoding="utf-8")
    click.echo(f"  [ok] API key generated: bg_{token[:8]}… (saved to {BG_HOME / 'api_token'})")
    click.echo("\nInit complete. Next: sudo behaveguard train --duration 60")


@cli.command()
@click.option("--duration", default=60, show_default=True, help="Observation minutes.")
@click.option("--process", default=None, help="Train only this process name.")
def train(duration: int, process: Optional[str]) -> None:
    """Observe running processes as 'normal' and train baseline models."""
    settings = _load_settings()
    from behaveguard.models.baseline_builder import BaselineBuilder

    click.echo(f"Observing running processes for {duration} minute(s)…")
    builder = BaselineBuilder(settings)
    results = builder.train_from_running_processes(duration)
    if process is not None:
        results = {process: results[process]} if process in results else {}

    if not results:
        click.echo("No baselines trained (no qualifying process activity observed).")
        return
    for name, result in results.items():
        click.echo(
            f"  [ok] {name}: baseline trained "
            f"(windows={result.num_windows}, threshold={result.threshold:.3f}, "
            f"val_loss={result.val_loss:.4f})"
        )


@cli.command()
@click.option("--no-dashboard", is_flag=True, help="Run headless (no Dash UI).")
def run(no_dashboard: bool) -> None:
    """Start monitoring: collector + scorer + alerts + API (+ dashboard)."""
    import threading

    import uvicorn

    settings = _load_settings()

    # Ensure the API and dashboard share one token.
    token = os.environ.get("BEHAVEGUARD_API_TOKEN")
    if not token:
        token = secrets.token_hex(16)
        os.environ["BEHAVEGUARD_API_TOKEN"] = token

    from behaveguard.api.server import create_app

    app = create_app(settings)
    api_config = uvicorn.Config(
        app, host=settings.api.host, port=settings.api.port, log_level="info"
    )
    api_server = uvicorn.Server(api_config)
    api_server.install_signal_handlers = lambda: None
    threading.Thread(target=api_server.run, daemon=True).start()

    if not no_dashboard:
        from behaveguard.dashboard.app import create_dashboard

        dash_app = create_dashboard(
            api_base_url=f"http://localhost:{settings.api.port}", api_token=token
        )
        threading.Thread(
            target=lambda: dash_app.run(
                host=settings.dashboard.host, port=settings.dashboard.port
            ),
            daemon=True,
        ).start()

    click.echo("🛡️  BehaveGuard running")
    click.echo(f"🔌  API:       http://localhost:{settings.api.port}")
    if not no_dashboard:
        click.echo(f"🌐  Dashboard: http://localhost:{settings.dashboard.port}")
    click.echo("Press Ctrl-C to stop.\n")

    try:
        asyncio.run(_monitor_loop(settings, app))
    except KeyboardInterrupt:
        click.echo("\nShutting down…")


async def _monitor_loop(settings, app) -> None:
    """Collect events, window them per process, score, and raise alerts."""
    from behaveguard.collector.ebpf_collector import EBPFCollector
    from behaveguard.features.window import PerProcessWindowManager
    from behaveguard.models.model_store import ModelStore
    from behaveguard.scoring.anomaly_scorer import AnomalyScorer

    state = app.state.bg
    event_store = state.event_store
    alert_manager = state.alert_manager
    await event_store.initialize()

    collector = EBPFCollector(settings)
    await collector.start()

    windows = PerProcessWindowManager(settings.features.window_seconds)
    scorer = AnomalyScorer(settings, ModelStore())
    score_interval = settings.features.window_seconds
    batch_size = int(settings.collection.event_batch_size)

    batch = []
    last_score = time.monotonic()
    try:
        async for event in collector.events():
            batch.append(event)
            windows.add_event(event)
            if len(batch) >= batch_size:
                await event_store.write_batch(batch)
                batch = []

            now = time.monotonic()
            if now - last_score >= score_interval:
                for pid in windows.get_all_pids():
                    window = windows.get_window(pid)
                    events = window.get_events() if window else []
                    if not events:
                        continue
                    verdict = scorer.score(events[-1].comm, events, pid)
                    if verdict.model_available:
                        await alert_manager.process(verdict)
                last_score = now
    finally:
        if batch:
            await event_store.write_batch(batch)
        await collector.stop()


@cli.command()
def status() -> None:
    """Show monitoring status: trained models and alert counts."""
    settings = _load_settings()
    from behaveguard.models.model_store import ModelStore
    from behaveguard.storage.alert_store import AlertStore

    models = ModelStore().list_models()
    click.echo(f"Trained models: {len(models)}")
    for meta in models:
        click.echo(f"  - {meta.get('process_name', '?')} "
                   f"(threshold={meta.get('threshold', 0):.3f})")

    async def _counts() -> int:
        return await AlertStore(settings).count_unacknowledged()

    unacked = asyncio.run(_counts())
    click.echo(f"Unacknowledged alerts: {unacked}")


@cli.command()
@click.option("--last", default="1h", show_default=True, help="Window, e.g. 30m, 1h, 7d.")
@click.option("--severity", default=None, help="Filter by severity.")
def alerts(last: str, severity: Optional[str]) -> None:
    """List recent alerts."""
    settings = _load_settings()
    from behaveguard.storage.alert_store import AlertStore

    since = datetime.now() - _parse_duration(last)

    async def _list():
        return await AlertStore(settings).list_alerts(
            severity=severity, from_time=since, limit=200
        )

    rows = asyncio.run(_list())
    if not rows:
        click.echo(f"No alerts in the last {last}.")
        return
    for alert in rows:
        click.echo(
            f"[{alert.severity}] {alert.process_name} (pid {alert.pid}) "
            f"score={alert.score:.0f} — {alert.explanation}"
        )


@cli.command()
@click.option("--pid", type=int, required=True, help="Process id to explain.")
def explain(pid: int) -> None:
    """Explain why a process looks suspicious, using its recent stored events."""
    settings = _load_settings()
    from behaveguard.models.model_store import ModelStore
    from behaveguard.scoring.anomaly_scorer import AnomalyScorer

    async def _events():
        return await settings_events(settings, pid)

    events = asyncio.run(_events())
    if not events:
        click.echo(f"No recent events stored for pid {pid}.")
        return

    scorer = AnomalyScorer(settings, ModelStore())
    verdict = scorer.score(events[-1].comm, events, pid)
    click.echo(f"PID {pid} ({events[-1].comm}) — score {verdict.final_score:.0f}/100 "
               f"[{verdict.severity}]")
    click.echo(verdict.explanation)


async def settings_events(settings, pid: int):
    """Load recent stored events for a pid (helper for ``explain``)."""
    from behaveguard.storage.event_store import EventStore

    store = EventStore(settings)
    return await store.query_by_pid(pid, 0, (1 << 63))


@cli.group()
def whitelist() -> None:
    """Manage known-safe processes/PIDs."""


@whitelist.command("add")
@click.option("--pid", type=int, default=None, help="Mark a PID as safe.")
@click.option("--process", default=None, help="Suppress alerts for a process name.")
def whitelist_add(pid: Optional[int], process: Optional[str]) -> None:
    """Whitelist a PID (suppress its scores) or a process name (suppression rule)."""
    if pid is None and process is None:
        raise click.UsageError("provide --pid or --process")

    BG_HOME.mkdir(parents=True, exist_ok=True)

    if pid is not None:
        safe = []
        if SAFE_PIDS_FILE.is_file():
            safe = json.loads(SAFE_PIDS_FILE.read_text(encoding="utf-8"))
        if pid not in safe:
            safe.append(pid)
        SAFE_PIDS_FILE.write_text(json.dumps(safe), encoding="utf-8")
        click.echo(f"  [ok] PID {pid} whitelisted ({SAFE_PIDS_FILE})")

    if process is not None:
        from behaveguard.alerts.rules_engine import RulesEngine, SuppressionRule

        engine = RulesEngine()
        engine.load()
        engine.add_rule(SuppressionRule(
            process_name=process, reason="cli whitelist", max_score_suppress=100.0,
            created_by="cli"))
        engine.save()
        click.echo(f"  [ok] process {process!r} whitelisted (suppression rule saved)")


def main() -> None:
    """Console-script entry point."""
    cli()


if __name__ == "__main__":
    main()
