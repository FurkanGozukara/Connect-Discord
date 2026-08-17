"""Command-line entry point for the source-only Discord bypass."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import time
from pathlib import Path

from . import __version__
from .diagnostics import DiagnosticResult, test_discord_tls
from .dns import DohResolver
from .launcher import (
    DiscordNotFoundError,
    is_discord_running,
    launch_discord,
    stop_discord,
)
from .policy import DomainPolicy
from .proxy import ProxyServer
from .tls import SPLIT_MODES


AUTO_SPLIT_MODES = ("tls-record", "tcp", "tls-record-aggressive", "tcp-aggressive")
PREFLIGHT_TIMEOUT_SECONDS = 6.0


def _default_domains_file() -> Path:
    return Path(__file__).resolve().parent.parent / "domains.txt"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="DiscordBypass",
        description=(
            "Run a loopback-only, Discord-only TLS splitting proxy and launch "
            "the official Discord desktop app through a local PAC file."
        ),
    )
    parser.add_argument(
        "--channel",
        choices=("stable", "ptb", "canary"),
        default="stable",
        help="installed official Discord channel to launch (default: stable)",
    )
    parser.add_argument(
        "--domains-file",
        type=Path,
        default=_default_domains_file(),
        help="editable allowlist file (default: domains.txt beside the package)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="localhost port; 0 chooses an unused ephemeral port (default: 0)",
    )
    parser.add_argument(
        "--split-delay-ms",
        type=float,
        default=12.0,
        help="delay between the first ClientHello fragments (default: 12 ms)",
    )
    parser.add_argument(
        "--split-mode",
        choices=("auto", *SPLIT_MODES),
        default="auto",
        help="ClientHello split strategy (default: test and select automatically)",
    )
    parser.add_argument(
        "--no-launch",
        action="store_true",
        help="run only the local proxy",
    )
    parser.add_argument(
        "--restart-discord",
        action="store_true",
        help="if Discord is running, close it before launching with proxy flags",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="perform a real certificate-validated discord.com test, then exit",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="show connection diagnostics (never message contents or tokens)",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s  %(levelname)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    if not verbose:
        # Hostnames are useful at INFO; routine connection teardown is DEBUG.
        logging.getLogger("asyncio").setLevel(logging.WARNING)


async def _wait_until_stopped() -> None:
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def request_stop(*_: object) -> None:
        loop.call_soon_threadsafe(stop_event.set)

    signal.signal(signal.SIGINT, request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_stop)
    await stop_event.wait()


async def _test_split_mode(proxy: ProxyServer) -> DiagnosticResult:
    return await asyncio.wait_for(
        asyncio.to_thread(
            test_discord_tls,
            proxy.host,
            proxy.port,
            timeout=PREFLIGHT_TIMEOUT_SECONDS,
        ),
        timeout=PREFLIGHT_TIMEOUT_SECONDS + 2.0,
    )


async def _select_split_mode(
    proxy: ProxyServer,
    requested_mode: str,
) -> DiagnosticResult:
    modes = AUTO_SPLIT_MODES if requested_mode == "auto" else (requested_mode,)
    failures: list[str] = []
    print("\nTesting this network and selecting a TLS split strategy...")
    for mode in modes:
        proxy.set_split_mode(mode)
        try:
            result = await _test_split_mode(proxy)
        except Exception as exc:
            failures.append(f"{mode}: {exc}")
            print(f"  {mode}: failed")
            continue
        print(f"  {mode}: passed")
        print(f"Selected split strategy: {mode}")
        return result
    raise ConnectionError("; ".join(failures))


async def _async_main(args: argparse.Namespace) -> int:
    try:
        policy = DomainPolicy.from_file(args.domains_file.resolve())
    except (OSError, ValueError) as exc:
        print(f"Allowlist error: {exc}", file=sys.stderr)
        return 2

    delay_seconds = args.split_delay_ms / 1000.0
    if not 0 <= args.port <= 65535:
        print("--port must be between 0 and 65535", file=sys.stderr)
        return 2
    if not 0 <= delay_seconds <= 0.25:
        print("--split-delay-ms must be between 0 and 250", file=sys.stderr)
        return 2

    resolver = DohResolver()
    proxy = ProxyServer(
        resolver,
        port=args.port,
        split_delay_seconds=delay_seconds,
        split_mode="tcp" if args.split_mode == "auto" else args.split_mode,
        policy=policy,
    )

    try:
        await proxy.start()
        print()
        print("DiscordBypass is active")
        print(f"  PAC:       {proxy.pac_url}")
        print(f"  Allowlist: {args.domains_file.resolve()} ({len(policy.suffixes)} suffixes)")
        print("  Security:  loopback only; HTTPS stays end-to-end encrypted")

        diagnostic_result: DiagnosticResult | None = None
        if args.diagnose or not args.no_launch or args.split_mode == "auto":
            try:
                diagnostic_result = await _select_split_mode(proxy, args.split_mode)
            except Exception as exc:
                print(f"\nNetwork preflight FAILED: {exc}", file=sys.stderr)
                print(
                    "No available split strategy completed a secure Discord connection.",
                    file=sys.stderr,
                )
                return 1

        if args.diagnose:
            assert diagnostic_result is not None
            print(
                "Diagnostic PASSED: "
                f"{diagnostic_result.tls_version}, {diagnostic_result.cipher}, "
                f"{diagnostic_result.http_status_line or 'HTTP response received'}"
            )
            return 0

        if not args.no_launch:
            if is_discord_running(args.channel):
                if not args.restart_discord:
                    print(
                        "\nDiscord is already running without this PAC. Close it and "
                        "rerun, or use --restart-discord.",
                        file=sys.stderr,
                    )
                    return 3
                print("\nRestarting Discord so the local PAC takes effect...")
                stop_discord(args.channel)
                deadline = time.monotonic() + 8.0
                while is_discord_running(args.channel) and time.monotonic() < deadline:
                    await asyncio.sleep(0.25)
                if is_discord_running(args.channel):
                    print("Discord did not exit in time.", file=sys.stderr)
                    return 3

            try:
                process = launch_discord(proxy.pac_url, channel=args.channel)
            except DiscordNotFoundError as exc:
                print(f"\nDiscord launch failed: {exc}", file=sys.stderr)
                return 4
            print(f"\nOfficial Discord launched (PID {process.pid}).")

        print("Keep this window open while using Discord. Press Ctrl+C to stop.")
        await _wait_until_stopped()
        print("\nStopping local proxy...")
        return 0
    finally:
        await proxy.stop()


def main() -> int:
    if sys.version_info < (3, 10):
        print("Python 3.10 or newer is required.", file=sys.stderr)
        return 2
    parser = _parser()
    args = parser.parse_args()
    _configure_logging(args.verbose)
    try:
        return asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
