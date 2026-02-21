#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["rich", "plotext"]
# ///
"""
pmtr – a lightweight MTR-like network path monitor with live charts.

Install uv (if needed):
    curl -LsSf https://astral.sh/uv/install.sh | sh

Usage:
    sudo uv run pmtr.py <destination>           # default: 8.8.8.8
    sudo uv run pmtr.py 1.1.1.1 --interval 0.5
    sudo uv run pmtr.py 8.8.8.8 --size 1400    # custom packet size

Controls:
    +/=   Increase chart time range
    -     Decrease chart time range
    c     Toggle latency chart
    p     Pause display updates
    s     Cycle sort column
    ?     Help panel
    q     Quit

Lint:
    uv tool run ruff check pmtr.py
    uv run --with pyright --with plotext pyright pmtr.py

Requires: Python 3.11+, root/sudo for raw ICMP sockets.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import deque
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import queue
import select
import signal
import socket
import struct
import sys
import termios
import threading
import time
import tty
from dataclasses import dataclass, field

import plotext as plt
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ─── ICMP helpers ────────────────────────────────────────────────────────────

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11


def _checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _extract_reply_ident(data: bytes) -> int | None:
    """Extract our ICMP ident from a response packet (after the 20-byte IP header).

    For Echo Reply (type 0): ident is at bytes 24-26 of the raw packet.
    For Time Exceeded (type 11): the original packet is embedded after the
    8-byte ICMP header, so ident is at bytes 20+8+20+4 = 52-54 (original
    IP header 20 bytes + ICMP type/code/checksum 4 bytes, then ident).
    """
    if len(data) < 28:
        return None
    icmp_type = data[20]
    if icmp_type == ICMP_ECHO_REPLY:
        return struct.unpack("!H", data[24:26])[0]
    elif icmp_type == ICMP_TIME_EXCEEDED:
        if len(data) >= 56:
            return struct.unpack("!H", data[52:54])[0]
    return None


def _build_icmp_packet(ident: int, seq: int, payload_size: int = 56) -> bytes:
    seq = seq & 0xFFFF  # ICMP sequence is 16-bit
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    payload = struct.pack("!d", time.time())  # 8 bytes timestamp
    # Pad payload to requested size (minimum 8 for timestamp)
    if payload_size > 8:
        payload += b"\x00" * (payload_size - 8)
    chk = _checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chk, ident, seq)
    return header + payload


# ─── Data model ──────────────────────────────────────────────────────────────


@dataclass
class HopStats:
    hop: int
    ip: str
    hostname: str
    sent: int = 0
    received: int = 0
    last_ms: float | None = None
    sum_ms: float = 0.0
    history: deque = field(default_factory=lambda: deque(maxlen=2400))  # ~10min @ 0.25s
    # Track stats since last full outage (100% loss burst)
    _sent_since_outage: int = 0
    _recv_since_outage: int = 0
    _sum_since_outage: float = 0.0
    _last_loss_time: float = 0.0  # monotonic timestamp of last loss (for flash)

    @property
    def avg_ms(self) -> float | None:
        return self.sum_ms / self.received if self.received else None

    @property
    def loss_pct(self) -> float:
        return ((self.sent - self.received) / self.sent * 100) if self.sent else 0.0

    @property
    def recent_loss_pct(self) -> float:
        """Loss % since last full outage reset."""
        if self._sent_since_outage == 0:
            return 0.0
        return (
            (self._sent_since_outage - self._recv_since_outage)
            / self._sent_since_outage
            * 100
        )

    @property
    def recent_avg_ms(self) -> float | None:
        """Average RTT since last full outage reset."""
        return (
            self._sum_since_outage / self._recv_since_outage
            if self._recv_since_outage
            else None
        )

    @property
    def jitter_ms(self) -> float | None:
        """Jitter: stddev of last 20 non-None RTT samples."""
        rtts = [rtt for _, rtt in list(self.history)[-80:] if rtt is not None]
        if len(rtts) < 2:
            return None
        mean = sum(rtts) / len(rtts)
        variance = sum((r - mean) ** 2 for r in rtts) / len(rtts)
        return variance**0.5

    def record_reply(self, rtt_ms: float) -> None:
        self.received += 1
        self.last_ms = rtt_ms
        self.sum_ms += rtt_ms
        self._recv_since_outage += 1
        self._sum_since_outage += rtt_ms

    def record_sent(self) -> None:
        """Called each cycle when a ping is sent."""
        self._sent_since_outage += 1

    def mark_loss(self) -> None:
        """Mark that the most recent ping was a loss."""
        self._last_loss_time = time.monotonic()

    def reset_recent(self) -> None:
        """Reset recent counters (called on full outage)."""
        self._sent_since_outage = 0
        self._recv_since_outage = 0
        self._sum_since_outage = 0.0


# ─── Outage tracking ────────────────────────────────────────────────────────


@dataclass
class HopSnapshot:
    """Point-in-time snapshot of a single hop during an outage."""

    hop: int
    ip: str
    hostname: str
    loss_pct: float
    avg_ms: float | None


def _fmt_duration(seconds: float) -> str:
    """Format seconds into a human-readable duration like '2m 30s' or '1h 5m'."""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    m, sec = divmod(s, 60)
    if m < 60:
        return f"{m}m {sec}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"


def _fmt_bad_hop(bad_hop: int | None, bad_host: str) -> str:
    """Format bad hop reference as 'hop N → N+1'."""
    if bad_hop is None:
        return ""
    return f"  hop {bad_hop - 1} → {bad_hop} ({bad_host})"


@dataclass
class OutageEvent:
    start: datetime
    end: datetime | None = None
    loss_pct: float = 0.0
    bad_hop: int | None = None  # first hop with significant loss
    bad_hop_host: str = ""  # hostname/ip of the bad hop
    hop_snapshots: list[HopSnapshot] = field(default_factory=list)

    @property
    def duration(self) -> float:
        end = self.end or datetime.now()
        return (end - self.start).total_seconds()

    def fmt(self) -> str:
        s = self.start.strftime("%Y-%m-%d %H:%M:%S")
        dur = _fmt_duration(self.duration)
        bad = _fmt_bad_hop(self.bad_hop, self.bad_hop_host)
        if self.end:
            return f"{s}  {dur:>8}  loss {self.loss_pct:.0f}%{bad}"
        else:
            return f"{s}  {dur:>8}  loss {self.loss_pct:.0f}%{bad}  [ONGOING]"

    def fmt_detail(self) -> str:
        """Multi-line detail showing per-hop loss during the outage."""
        lines = [self.fmt()]
        for snap in self.hop_snapshots:
            marker = ">>" if snap.hop == self.bad_hop else "  "
            host = snap.hostname if snap.hostname != snap.ip else snap.ip
            rtt = f"{snap.avg_ms:.1f}ms" if snap.avg_ms is not None else "—"
            lines.append(
                f"    {marker} hop {snap.hop:>2}  {host:<24} loss {snap.loss_pct:>5.1f}%  avg {rtt}"
            )
        return "\n".join(lines)


def _recent_loss(h: HopStats, window: int = 16) -> float:
    """Compute loss % over the last `window` history entries."""
    if not h.history or h.ip == "*":
        return 100.0
    recent = list(h.history)[-window:]
    if not recent:
        return 0.0
    lost = sum(1 for _, rtt in recent if rtt is None)
    return lost / len(recent) * 100


def _snapshot_hops(hops: list[HopStats]) -> tuple[list[HopSnapshot], int | None, str]:
    """Snapshot current hop stats, detect the first hop where loss spikes.

    Uses recent history (last 16 samples) instead of cumulative stats so that
    a hop which just started failing is correctly identified.
    """
    snapshots = []
    bad_hop = None
    bad_host = ""
    prev_loss = 0.0
    worst_loss = 0.0
    worst_hop = None
    worst_host = ""
    for h in hops:
        if h.ip == "*":
            snapshots.append(HopSnapshot(h.hop, h.ip, h.hostname, 100.0, None))
            continue
        loss = _recent_loss(h)
        snapshots.append(HopSnapshot(h.hop, h.ip, h.hostname, loss, h.avg_ms))
        host = h.hostname if h.hostname != h.ip else h.ip
        # Detect bad hop: first hop where loss jumps significantly
        if bad_hop is None and loss > 20 and (loss - prev_loss) > 15:
            bad_hop = h.hop
            bad_host = host
        # Track the hop with the worst loss as fallback
        if loss > worst_loss:
            worst_loss = loss
            worst_hop = h.hop
            worst_host = host
        prev_loss = loss
    # Fallback: if no jump detected, use the hop with the highest loss
    if bad_hop is None and worst_hop is not None and worst_loss > 0:
        bad_hop = worst_hop
        bad_host = worst_host
    return snapshots, bad_hop, bad_host


class OutageTracker:
    def __init__(
        self,
        threshold_pct: float = 20.0,
        min_duration: float = 1.0,
        window_size: int = 16,
    ):
        self.threshold_pct = threshold_pct
        self.min_duration = min_duration
        self._window: deque[bool] = deque(maxlen=window_size)
        self._current_outage: OutageEvent | None = None
        self.events: list[OutageEvent] = []

    def record(self, got_reply: bool, hops: list[HopStats] | None = None) -> None:
        self._window.append(got_reply)
        if len(self._window) < 4:
            return
        lost = sum(1 for r in self._window if not r)
        loss_pct = lost / len(self._window) * 100
        if loss_pct >= self.threshold_pct:
            if self._current_outage is None:
                snaps, bad_hop, bad_host = (
                    _snapshot_hops(hops) if hops else ([], None, "")
                )
                self._current_outage = OutageEvent(
                    start=datetime.now(),
                    loss_pct=loss_pct,
                    bad_hop=bad_hop,
                    bad_hop_host=bad_host,
                    hop_snapshots=snaps,
                )
            else:
                self._current_outage.loss_pct = loss_pct
                # Re-snapshot periodically to track shifting bad hop
                if hops:
                    snaps, bad_hop, bad_host = _snapshot_hops(hops)
                    self._current_outage.hop_snapshots = snaps
                    if bad_hop is not None:
                        self._current_outage.bad_hop = bad_hop
                        self._current_outage.bad_hop_host = bad_host
        else:
            if self._current_outage is not None:
                self._current_outage.end = datetime.now()
                if self._current_outage.duration >= self.min_duration:
                    self.events.append(self._current_outage)
                self._current_outage = None

    @property
    def active_outage(self) -> OutageEvent | None:
        if self._current_outage and self._current_outage.duration >= self.min_duration:
            return self._current_outage
        return None


# ─── Route discovery (traceroute) ──────────────────────────────────────────


async def discover_route(
    dest: str, max_hops: int = 30, timeout: float = 2.0, payload_size: int = 56
) -> list[HopStats]:
    console = Console(stderr=True)
    console.print(f"[bold cyan]Discovering route to {dest}...[/]")
    dest_ip = socket.gethostbyname(dest)
    hops: list[HopStats] = []
    ident = os.getpid() & 0xFFFF

    for ttl in range(1, max_hops + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            console.print(
                "[bold red]Error:[/] Raw sockets require root. Run with sudo."
            )
            sys.exit(1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sock.settimeout(timeout)
        pkt = _build_icmp_packet(ident, ttl, payload_size)
        sock.sendto(pkt, (dest_ip, 0))
        addr = "*"
        try:
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                data, (resp_addr, _) = sock.recvfrom(1024)
                # Validate this is a response to OUR probe
                reply_ident = _extract_reply_ident(data)
                if reply_ident == ident:
                    addr = resp_addr
                    break
                # Not ours — keep listening
        except socket.timeout:
            pass
        finally:
            sock.close()
        hostname = addr
        if addr != "*":
            try:
                hostname = socket.gethostbyaddr(addr)[0]
            except (socket.herror, socket.gaierror):
                hostname = addr
        console.print(f"  [dim]{ttl:>2}[/]  {addr:<16} {hostname}")
        hops.append(HopStats(hop=ttl, ip=addr, hostname=hostname))
        if addr == dest_ip:
            break

    console.print(f"[bold green]Route discovered:[/] {len(hops)} hops\n")
    return hops


# ─── Async pinger ───────────────────────────────────────────────────────────

_error_count = 0


async def ping_hop(
    stats: HopStats, ident: int, seq: int, timeout: float = 1.5, payload_size: int = 56
) -> None:
    global _error_count
    if stats.ip == "*":
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return

    pkt = _build_icmp_packet(ident, seq, payload_size)
    target_ip = stats.ip
    stats.sent += 1

    def _do_ping() -> float | None:
        """Blocking send+recv in a thread. Returns RTT in ms or None."""
        t0 = time.monotonic()
        sock.sendto(pkt, (target_ip, 0))
        deadline = t0 + timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, (resp_addr, _) = sock.recvfrom(1024)
            except (socket.timeout, OSError):
                return None

            # Must match our ident
            reply_ident = _extract_reply_ident(data)
            if reply_ident != ident:
                continue

            icmp_type = data[20]
            if icmp_type == ICMP_ECHO_REPLY and resp_addr == target_ip:
                return (time.monotonic() - t0) * 1000
            elif icmp_type == ICMP_TIME_EXCEEDED:
                # Time Exceeded can come from any router — accept from any source
                return (time.monotonic() - t0) * 1000
            # else: unrelated ICMP, keep listening

    try:
        loop = asyncio.get_event_loop()
        rtt = await asyncio.wait_for(
            loop.run_in_executor(None, _do_ping),
            timeout=timeout + 0.5,
        )
        if rtt is not None:
            stats.record_reply(rtt)
    except asyncio.TimeoutError:
        pass
    except Exception:
        _error_count += 1
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ─── Chart ──────────────────────────────────────────────────────────────────

TIME_RANGES = [15, 30, 60, 120, 300, 600]
HOP_COLORS = ["cyan", "green", "yellow", "magenta", "blue", "orange", "white", "red+"]

SORT_KEYS = ["hop", "loss%", "avg", "last", "jitter"]


def build_chart(hops: list[HopStats], time_range: int, width: int, height: int) -> str:
    """Render a plotext latency chart and return as a string."""
    plt.clf()
    plt.plotsize(width, height)
    plt.theme("dark")
    plt.title(f"Latency  ─  {time_range}s window  ─  [+/-] adjust  [c] hide  [q] quit")
    plt.xlabel("Seconds ago")
    plt.ylabel("ms")

    now = time.monotonic()
    cutoff = now - time_range
    has_data = False
    max_rtt = 0.0
    all_loss_x: list[float] = []

    for i, hop in enumerate(hops):
        if hop.ip == "*" or not hop.history:
            continue

        times: list[float] = []
        rtts: list[float] = []

        for ts, rtt in hop.history:
            if ts < cutoff:
                continue
            age = ts - now  # negative (seconds ago)
            if rtt is not None:
                times.append(age)
                rtts.append(rtt)
                if rtt > max_rtt:
                    max_rtt = rtt
            else:
                all_loss_x.append(age)

        if times:
            color = HOP_COLORS[i % len(HOP_COLORS)]
            label = (
                f"{hop.hop}:{hop.hostname}"
                if hop.hostname != hop.ip
                else f"{hop.hop}:{hop.ip}"
            )
            # Truncate label to keep legend tidy
            if len(label) > 22:
                label = label[:20] + ".."
            plt.plot(times, rtts, label=label, color=color)
            has_data = True

    if all_loss_x:
        # Pin loss markers at the top of the chart
        top_y = max_rtt * 1.15 if max_rtt > 0 else 10.0
        plt.scatter(
            all_loss_x,
            [top_y] * len(all_loss_x),
            marker="▼",
            color="red",
            label="LOSS",
        )

    if not has_data and not all_loss_x:
        plt.plot([0], [0], label="waiting…")

    return plt.build()


# ─── Display ────────────────────────────────────────────────────────────────


def build_table(
    hops: list[HopStats],
    dest: str,
    web_url: str = "",
    paused: bool = False,
    pkt_size: int = 64,
    sort_key: str = "hop",
) -> Table:
    err_tag = f"  [dim red]({_error_count} errors)[/]" if _error_count else ""
    paused_tag = "  [bold yellow]⏸ PAUSED[/]" if paused else ""
    size_tag = f"  [dim]({pkt_size}B)[/]" if pkt_size != 64 else ""
    sort_tag = f"  [dim yellow]▼ {sort_key}[/]" if sort_key != "hop" else ""
    url_tag = f"  [dim cyan]{web_url}[/]" if web_url else ""
    table = Table(
        title=f"[bold]pmtr[/]  →  [cyan]{dest}[/]{err_tag}{paused_tag}{size_tag}{sort_tag}{url_tag}",
        title_style="bold",
        show_lines=False,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Host", overflow="ellipsis", no_wrap=True)
    table.add_column("IP", style="dim cyan", min_width=15, no_wrap=True)
    table.add_column("Loss%", justify="right", width=7)
    table.add_column("Rcnt%", justify="right", width=7)
    table.add_column("Loss", justify="right", width=6)
    table.add_column("Sent", justify="right", width=6, style="dim")
    table.add_column("Recv", justify="right", width=6, style="dim")
    table.add_column("Last", justify="right", width=9)
    table.add_column("Avg", justify="right", width=9)
    table.add_column("RAvg", justify="right", width=9)
    table.add_column("Jtr", justify="right", width=9)

    # Sort hops if not default order
    display_hops = hops
    if sort_key == "loss%":
        display_hops = sorted(hops, key=lambda h: h.loss_pct, reverse=True)
    elif sort_key == "avg":
        display_hops = sorted(hops, key=lambda h: h.avg_ms or 0, reverse=True)
    elif sort_key == "last":
        display_hops = sorted(hops, key=lambda h: h.last_ms or 0, reverse=True)
    elif sort_key == "jitter":
        display_hops = sorted(hops, key=lambda h: h.jitter_ms or 0, reverse=True)

    for h in display_hops:
        loss = h.loss_pct
        recent_loss = h.recent_loss_pct
        loss_count = h.sent - h.received
        loss_style = "green" if loss == 0 else ("yellow" if loss < 10 else "bold red")
        recent_style = (
            "green"
            if recent_loss == 0
            else ("yellow" if recent_loss < 10 else "bold red")
        )
        # Flash the entire row red when last ping was a loss
        # Flash row red for ~1.5s after a loss, fading out
        loss_age = time.monotonic() - h._last_loss_time
        if loss_age < 1.5:
            fade = 1.0 - loss_age / 1.5  # 1.0 → 0.0
            r = int(180 * fade)
            row_style = f"on #{r:02x}1015"
        else:
            row_style = ""

        def fmt(v: float | None) -> str:
            return f"{v:.1f} ms" if v is not None else "—"

        table.add_row(
            str(h.hop),
            h.hostname if h.hostname != h.ip else "—",
            h.ip,
            f"[{loss_style}]{loss:.1f}%[/]",
            f"[{recent_style}]{recent_loss:.1f}%[/]",
            f"[{loss_style}]{loss_count}[/]",
            str(h.sent),
            str(h.received),
            fmt(h.last_ms),
            fmt(h.avg_ms),
            fmt(h.recent_avg_ms),
            fmt(h.jitter_ms),
            style=row_style,
        )

    return table


def _build_help_panel() -> Panel:
    """Build a help overlay panel."""
    help_text = Text()
    help_text.append("  pmtr – keyboard shortcuts\n\n", style="bold cyan")
    keys = [
        ("?", "Toggle this help panel"),
        ("+/=", "Increase chart time range"),
        ("-", "Decrease chart time range"),
        ("c", "Toggle latency chart"),
        ("p", "Pause display updates"),
        ("s", "Cycle sort column"),
        ("q", "Quit"),
    ]
    for key, desc in keys:
        help_text.append(f"  {key:<8}", style="bold yellow")
        help_text.append(f"{desc}\n", style="dim")
    help_text.append("\n")
    help_text.append("  Columns\n", style="bold cyan")
    cols = [
        ("Loss%", "Overall packet loss since start"),
        ("Rcnt%", "Loss since last full outage"),
        ("RAvg", "Average RTT since last full outage"),
        ("Jtr", "Jitter (RTT std deviation)"),
    ]
    for col, desc in cols:
        help_text.append(f"  {col:<8}", style="bold")
        help_text.append(f"{desc}\n", style="dim")
    help_text.append("\n  Press ", style="dim")
    help_text.append("?", style="bold yellow")
    help_text.append(" to close", style="dim")
    return Panel(
        help_text,
        title="[bold]Help[/]",
        border_style="cyan",
        expand=True,
    )


def build_display(
    hops: list[HopStats],
    dest: str,
    tracker: OutageTracker,
    time_range: int,
    term_w: int,
    term_h: int,
    show_chart: bool = True,
    show_help: bool = False,
    paused: bool = False,
    pkt_size: int = 64,
    sort_key: str = "hop",
    web_url: str = "",
) -> Layout:
    """Assemble the full layout: table + chart + outage log."""
    layout = Layout()

    # ── Help overlay ──
    if show_help:
        table = build_table(
            hops, dest, web_url, paused=paused, pkt_size=pkt_size, sort_key=sort_key
        )
        table_height = len(hops) + 5
        help_panel = _build_help_panel()
        layout.split_column(
            Layout(table, name="table", size=table_height),
            Layout(help_panel, name="help"),
        )
        return layout

    # ── Outage log panel ──
    log_lines = Text()
    active = tracker.active_outage
    past = tracker.events[-8:]
    if not past and not active:
        log_lines.append("  No notable outages recorded.", style="dim green")
    else:
        for evt in past:
            log_lines.append(f"  ● {evt.fmt()}\n", style="yellow")
            # Show the bad hop for resolved outages
            if evt.bad_hop is not None:
                for snap in evt.hop_snapshots:
                    if snap.hop == evt.bad_hop:
                        host = snap.hostname if snap.hostname != snap.ip else snap.ip
                        rtt = f"{snap.avg_ms:.1f}ms" if snap.avg_ms is not None else "—"
                        log_lines.append(
                            f"    ▸▸ hop {snap.hop - 1} → {snap.hop}  {host:<24} "
                            f"loss {snap.loss_pct:>5.1f}%  avg {rtt}\n",
                            style="red",
                        )
                        break
        if active:
            log_lines.append(f"  ▶ {active.fmt()}\n", style="bold red")
            # Show per-hop detail for the active outage
            for snap in active.hop_snapshots:
                if snap.ip == "*":
                    continue
                is_bad = snap.hop == active.bad_hop
                marker = "▸▸" if is_bad else "  "
                style = "bold red" if is_bad else "dim"
                host = snap.hostname if snap.hostname != snap.ip else snap.ip
                rtt = f"{snap.avg_ms:.1f}ms" if snap.avg_ms is not None else "—"
                hop_label = (
                    f"{snap.hop - 1} → {snap.hop}" if is_bad else f"{snap.hop:>5}"
                )
                log_lines.append(
                    f"    {marker} hop {hop_label}  {host:<24} "
                    f"loss {snap.loss_pct:>5.1f}%  avg {rtt}\n",
                    style=style,
                )
    past_detail_lines = sum(1 for e in past if e.bad_hop is not None)
    active_snap_lines = len(active.hop_snapshots) if active else 0
    outage_height = min(
        3 + len(past) + past_detail_lines + (1 if active else 0) + active_snap_lines, 25
    )
    outage_panel = Panel(
        log_lines,
        title=f"[bold]Outage Log[/] [dim](>{tracker.threshold_pct:.0f}% loss for >{tracker.min_duration:.0f}s)[/]",
        border_style="red" if active else "dim",
        expand=True,
    )

    # ── Hop table ──
    table = build_table(
        hops, dest, web_url, paused=paused, pkt_size=pkt_size, sort_key=sort_key
    )
    table_height = len(hops) + 5

    if show_chart:
        # ── Chart panel ──
        chart_h = max(term_h - table_height - outage_height - 4, 6)
        chart_w = max(term_w - 6, 40)
        try:
            chart_str = build_chart(hops, time_range, chart_w, chart_h)
            chart_content = Text.from_ansi(chart_str)
        except Exception:
            chart_content = Text("  Chart loading…", style="dim")
        chart_panel = Panel(chart_content, border_style="cyan dim", expand=True)

        layout.split_column(
            Layout(table, name="table", size=table_height),
            Layout(chart_panel, name="chart"),
            Layout(outage_panel, name="log", size=outage_height),
        )
    else:
        layout.split_column(
            Layout(table, name="table"),
            Layout(outage_panel, name="log", size=outage_height),
        )
    return layout


# ─── Keyboard listener ─────────────────────────────────────────────────────


async def keyboard_listener(stop: asyncio.Event, state: dict) -> None:
    """Listen for +/- keypresses to adjust chart time range (cbreak mode)."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        loop = asyncio.get_event_loop()
        while not stop.is_set():
            ready, _, _ = await loop.run_in_executor(
                None, lambda: select.select([fd], [], [], 0.15)
            )
            if ready:
                ch = os.read(fd, 1)
                if ch in (b"+", b"="):
                    state["idx"] = min(state["idx"] + 1, len(TIME_RANGES) - 1)
                elif ch == b"-":
                    state["idx"] = max(state["idx"] - 1, 0)
                elif ch == b"c":
                    state["chart"] = not state["chart"]
                elif ch == b"p":
                    state["paused"] = not state["paused"]
                elif ch == b"s":
                    keys = SORT_KEYS
                    state["sort"] = keys[(keys.index(state["sort"]) + 1) % len(keys)]
                elif ch == b"?":
                    state["help"] = not state["help"]
                elif ch in (b"q", b"\x03"):  # q or Ctrl+C
                    stop.set()
    except asyncio.CancelledError:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


# ─── Web dashboard ──────────────────────────────────────────────────────────

_WEB_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>pmtr – Network Monitor</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --dim: #7d8590; --green: #3fb950;
    --yellow: #d29922; --red: #f85149; --cyan: #58a6ff;
    --accent: #1f6feb;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    background: var(--bg); color: var(--text);
    padding: 8px; font-size: 13px;
  }
  h1 {
    font-size: 16px; padding: 10px 12px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; margin-bottom: 8px;
    display: flex; justify-content: space-between; align-items: center;
  }
  h1 .dest { color: var(--cyan); }
  h1 .status { font-size: 11px; color: var(--dim); }
  h1 .err { color: var(--red); font-size: 11px; margin-left: 8px; }
  .controls {
    display: flex; gap: 6px; align-items: center;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 6px 10px; margin-bottom: 8px;
    font-size: 12px;
  }
  .controls button {
    background: var(--bg); color: var(--text); border: 1px solid var(--border);
    border-radius: 4px; padding: 3px 10px; cursor: pointer;
    font-family: inherit; font-size: 12px;
    transition: background 0.15s, border-color 0.15s;
  }
  .controls button:hover { border-color: var(--cyan); background: var(--surface); }
  .controls button.active { border-color: var(--cyan); background: var(--accent); color: #fff; }
  .controls .sep { color: var(--border); margin: 0 4px; }
  .controls .label { color: var(--dim); }
  .controls .time-val { color: var(--cyan); min-width: 36px; text-align: center; font-weight: 700; }
  .tbl-wrap {
    overflow-x: auto; -webkit-overflow-scrolling: touch;
    border: 1px solid var(--border); border-radius: 8px;
    background: var(--surface); margin-bottom: 8px;
  }
  table { width: 100%; border-collapse: separate; border-spacing: 0; white-space: nowrap; }
  th {
    position: sticky; top: 0; background: var(--surface);
    border-bottom: 2px solid var(--border);
    padding: 6px 8px; text-align: right; color: var(--dim); font-size: 11px;
  }
  th:nth-child(1), th:nth-child(2), th:nth-child(3) { text-align: left; }
  th:nth-child(1), td:nth-child(1) {
    position: sticky; left: 0; z-index: 2; background: var(--surface);
    border-right: 1px solid var(--border);
  }
  th:nth-child(1) { z-index: 3; }
  th.sortable { cursor: pointer; user-select: none; }
  th.sortable:hover { color: var(--cyan); }
  th .sort-arrow { font-size: 9px; margin-left: 2px; }
  td {
    padding: 5px 8px; border-bottom: 1px solid var(--border);
    text-align: right; font-variant-numeric: tabular-nums;
    transition: background-color 0.3s ease;
  }
  td:nth-child(1) { text-align: left; color: var(--dim); width: 28px; }
  td:nth-child(2) { text-align: left; max-width: 180px; overflow: hidden; text-overflow: ellipsis; }
  td:nth-child(3) { text-align: left; color: var(--cyan); opacity: .7; }
  td:nth-child(n+4) { min-width: 72px; }
  tr:last-child td { border-bottom: none; }
  tr.loss-flash td { background-color: rgba(248, 81, 73, 0.35) !important; }
  @keyframes flash-loss {
    0% { background-color: rgba(248, 81, 73, 0.5); }
    100% { background-color: transparent; }
  }
  tr.loss-flash td { animation: flash-loss 1.5s ease-out; }
  .loss-ok { color: var(--green); }
  .loss-warn { color: var(--yellow); }
  .loss-bad { color: var(--red); font-weight: 700; }
  .chart-wrap {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 10px; margin-bottom: 8px;
    position: relative; height: 260px;
  }
  .chart-wrap canvas { width: 100% !important; height: 100% !important; }
  .chart-wrap.hidden { display: none; }
  .help-overlay {
    background: var(--surface); border: 1px solid var(--cyan);
    border-radius: 8px; padding: 16px 20px; margin-bottom: 8px;
  }
  .help-overlay.hidden { display: none; }
  .help-overlay h2 { font-size: 14px; color: var(--cyan); margin-bottom: 10px; }
  .help-overlay .row { display: flex; padding: 2px 0; font-size: 12px; }
  .help-overlay .key { color: var(--yellow); font-weight: 700; min-width: 60px; }
  .help-overlay .desc { color: var(--dim); }
  .help-overlay .section { color: var(--cyan); font-weight: 700; margin-top: 10px; margin-bottom: 4px; font-size: 13px; }
  .outages {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 10px 12px;
  }
  .outages h2 {
    font-size: 13px; color: var(--dim); margin-bottom: 6px;
    display: flex; justify-content: space-between;
  }
  .outages h2 .badge {
    background: var(--red); color: #fff; font-size: 10px;
    padding: 1px 6px; border-radius: 10px;
  }
  .evt { padding: 3px 0; font-size: 12px; }
  .evt.past { color: var(--yellow); }
  .evt.active { color: var(--red); font-weight: 700; }
  .evt .bad { color: var(--red); }
  .snap { padding-left: 16px; font-size: 11px; color: var(--dim); }
  .snap.is-bad { color: var(--red); font-weight: 700; }
  .none { color: var(--green); opacity: .6; }
  @media (max-width: 600px) {
    body { font-size: 12px; padding: 4px; }
    td, th { padding: 4px 5px; }
    td:nth-child(n+4) { min-width: 56px; }
    .chart-wrap { height: 200px; }
  }
  .copyable { cursor: pointer; border-bottom: 1px dashed transparent; transition: border-color 0.2s; }
  .copyable:hover { border-bottom-color: var(--cyan); }
  @keyframes copy-flash { 0% { background: var(--cyan); color: var(--bg); } 100% { background: transparent; } }
  .copied { animation: copy-flash 0.4s ease-out; border-radius: 2px; }
</style>
</head>
<body>
<h1>
  <span>pmtr &rarr; <span class="dest" id="dest">&hellip;</span><span class="err" id="errTag"></span></span>
  <span class="status" id="status">connecting&hellip;</span>
</h1>
<div class="controls">
  <span class="label">Chart</span>
  <button id="btnMinus" title="Decrease time range (-)">&#x2212;</button>
  <span class="time-val" id="timeVal">60s</span>
  <button id="btnPlus" title="Increase time range (+)">+</button>
  <span class="sep">|</span>
  <button id="btnChart" class="active" title="Toggle chart (c)">Chart</button>
  <button id="btnPause" title="Pause updates (p)">Pause</button>
  <button id="btnHelp" title="Help (?)">?</button>
</div>
<div class="tbl-wrap">
<table>
<thead><tr>
  <th>#</th><th>Host</th><th>IP</th>
  <th class="sortable" data-sort="loss_pct">Loss%</th><th>Rcnt%</th><th class="sortable" data-sort="loss_count">Loss</th>
  <th>Sent</th><th>Recv</th>
  <th class="sortable" data-sort="last">Last</th><th class="sortable" data-sort="avg">Avg</th><th>RAvg</th><th class="sortable" data-sort="jitter">Jtr</th>
</tr></thead>
<tbody id="hops"></tbody>
</table>
</div>
<div class="chart-wrap" id="chartWrap"><canvas id="latencyChart"></canvas></div>
<div class="help-overlay hidden" id="helpPanel">
  <h2>pmtr &ndash; Controls</h2>
  <div class="section">Keyboard Shortcuts</div>
  <div class="row"><span class="key">+ / =</span><span class="desc">Increase chart time range</span></div>
  <div class="row"><span class="key">&minus;</span><span class="desc">Decrease chart time range</span></div>
  <div class="row"><span class="key">c</span><span class="desc">Toggle latency chart</span></div>
  <div class="row"><span class="key">p</span><span class="desc">Pause display updates</span></div>
  <div class="row"><span class="key">s</span><span class="desc">Cycle sort column</span></div>
  <div class="row"><span class="key">q</span><span class="desc">Quit (terminal only)</span></div>
  <div class="row"><span class="key">?</span><span class="desc">Toggle this help panel</span></div>
  <div class="row"><span class="key">click</span><span class="desc">Click host/IP to copy to clipboard</span></div>
  <div class="section">Columns</div>
  <div class="row"><span class="key">Loss%</span><span class="desc">Overall packet loss since start</span></div>
  <div class="row"><span class="key">Rcnt%</span><span class="desc">Loss since last full outage</span></div>
  <div class="row"><span class="key">RAvg</span><span class="desc">Average RTT since last full outage</span></div>
  <div class="row"><span class="key">Jtr</span><span class="desc">Jitter (RTT std deviation)</span></div>
</div>
<div class="outages">
  <h2>Outage Log <span class="badge" id="outageBadge" style="display:none">ACTIVE</span></h2>
  <div id="outageList"><span class="none">No notable outages recorded.</span></div>
</div>
<script>
function ms(v){if(v==null)return '\u2014';var s=v.toFixed(1)+' ms';return s.padStart(8,'\u00a0');}
function lc(pct){return pct===0?'loss-ok':pct<10?'loss-warn':'loss-bad';}

// State
const TIME_RANGES=[15,30,60,120,300,600];
let timeIdx=2;
let showChart=true;
let showHelp=false;
let paused=false;
let lastChartData=null;
let bufferedMsg=null;
let sortCol=null;
let sortDir=-1;

function fmtTime(s){return s>=60?(s/60)+'m':s+'s';}
function syncUI(){
  document.getElementById('timeVal').textContent=fmtTime(TIME_RANGES[timeIdx]);
  var cw=document.getElementById('chartWrap');
  if(showChart){cw.classList.remove('hidden');}else{cw.classList.add('hidden');}
  var bc=document.getElementById('btnChart');
  if(showChart){bc.classList.add('active');}else{bc.classList.remove('active');}
  var hp=document.getElementById('helpPanel');
  if(showHelp){hp.classList.remove('hidden');}else{hp.classList.add('hidden');}
  var bh=document.getElementById('btnHelp');
  if(showHelp){bh.classList.add('active');}else{bh.classList.remove('active');}
  if(showChart && lastChartData) updateChart(lastChartData);
  var bp=document.getElementById('btnPause');
  if(paused){bp.classList.add('active');bp.textContent='\u25b6 Resume';}else{bp.classList.remove('active');bp.textContent='Pause';}
  // Sort indicators
  document.querySelectorAll('th.sortable').forEach(function(th){
    var base=th.textContent.replace(/[\u25b2\u25bc\s]/g,'');
    if(th.getAttribute('data-sort')===sortCol){th.innerHTML=base+'<span class="sort-arrow"> \u25bc</span>';}
    else{th.textContent=base;}
  });
}
function doPlus(){timeIdx=Math.min(timeIdx+1,TIME_RANGES.length-1);syncUI();}
function doMinus(){timeIdx=Math.max(timeIdx-1,0);syncUI();}
function doChart(){showChart=!showChart;syncUI();}
function doHelp(){showHelp=!showHelp;syncUI();}
function doPause(){paused=!paused;if(!paused&&bufferedMsg){renderData(bufferedMsg);bufferedMsg=null;}syncUI();}
var SORT_COLS=['loss_pct','loss_count','last','avg','jitter'];
function doSort(){
  if(!sortCol){sortCol=SORT_COLS[0];}
  else{var i=SORT_COLS.indexOf(sortCol);sortCol=i<SORT_COLS.length-1?SORT_COLS[i+1]:null;}
  if(lastRendered)renderData(lastRendered);syncUI();
}
function doSortCol(col){
  if(sortCol===col){sortCol=null;}else{sortCol=col;}
  if(lastRendered)renderData(lastRendered);syncUI();
}
document.querySelectorAll('th.sortable').forEach(function(th){
  th.onclick=function(){doSortCol(th.getAttribute('data-sort'));};
});

document.getElementById('btnPlus').onclick=doPlus;
document.getElementById('btnMinus').onclick=doMinus;
document.getElementById('btnChart').onclick=doChart;
document.getElementById('btnPause').onclick=doPause;
document.getElementById('btnHelp').onclick=doHelp;

document.addEventListener('keydown',function(e){
  if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA')return;
  if(e.key==='+'||e.key==='=')doPlus();
  else if(e.key==='-')doMinus();
  else if(e.key==='c')doChart();
  else if(e.key==='p')doPause();
  else if(e.key==='s')doSort();
  else if(e.key==='?')doHelp();
});

// Chart
var hopColors=['#58a6ff','#3fb950','#d29922','#bc8cff','#79c0ff','#f0883e','#e6edf3','#ff7b72'];
var chart=null;
function initChart(){
  var ctx=document.getElementById('latencyChart').getContext('2d');
  chart=new Chart(ctx,{
    type:'line',
    data:{datasets:[]},
    options:{
      responsive:true, maintainAspectRatio:false,
      animation:false,
      scales:{
        x:{
          type:'linear', title:{display:true,text:'Seconds ago',color:'#7d8590'},
          ticks:{color:'#7d8590'}, grid:{color:'rgba(48,54,61,0.5)'},
          reverse:false
        },
        y:{
          title:{display:true,text:'ms',color:'#7d8590'},
          ticks:{color:'#7d8590'}, grid:{color:'rgba(48,54,61,0.5)'},
          beginAtZero:true
        }
      },
      plugins:{
        legend:{labels:{color:'#e6edf3',font:{family:"'SF Mono',monospace",size:10},boxWidth:12,padding:8}}
      },
      elements:{point:{radius:0},line:{borderWidth:1.5}}
    }
  });
}

function updateChart(chartData){
  if(!showChart)return;
  if(!chart)initChart();
  if(!chartData||!chartData.length)return;
  var cutoff=-TIME_RANGES[timeIdx];
  var datasets=[];
  for(var i=0;i<chartData.length;i++){
    var hop=chartData[i];
    if(!hop.points||!hop.points.length)continue;
    var pts=[];
    for(var j=0;j<hop.points.length;j++){
      if(hop.points[j][0]>=cutoff) pts.push({x:hop.points[j][0],y:hop.points[j][1]});
    }
    if(!pts.length)continue;
    datasets.push({
      label:hop.label,
      data:pts,
      borderColor:hopColors[i%hopColors.length],
      backgroundColor:'transparent',
      tension:0.2
    });
  }
  var lossPoints=[];
  for(var k=0;k<chartData.length;k++){
    var lh=chartData[k];
    if(lh.loss){for(var l=0;l<lh.loss.length;l++){if(lh.loss[l]>=cutoff)lossPoints.push(lh.loss[l]);}}
  }
  if(lossPoints.length){
    var maxY=10;
    for(var m=0;m<datasets.length;m++){var dd=datasets[m].data;for(var n=0;n<dd.length;n++){if(dd[n].y>maxY)maxY=dd[n].y;}}
    var topY=maxY*1.15;
    var ld=[];for(var o=0;o<lossPoints.length;o++)ld.push({x:lossPoints[o],y:topY});
    datasets.push({label:'LOSS',data:ld,borderColor:'transparent',backgroundColor:'#f85149',pointRadius:4,pointStyle:'triangle',showLine:false});
  }
  chart.options.scales.x.min=cutoff;
  chart.options.scales.x.max=0;
  chart.data.datasets=datasets;
  chart.update();
}

// SSE
var es=new EventSource('/events');
var lastRendered=null;
function renderData(d){
  lastRendered=d;
  document.getElementById('dest').textContent=d.dest;
  document.getElementById('status').textContent='seq '+d.seq+'  \u2022  '+d.uptime;
  var et=document.getElementById('errTag');
  et.textContent=d.errors?'('+d.errors+' errors)':'';

  var hops=d.hops.slice();
  if(sortCol){
    hops.sort(function(a,b){return (b[sortCol]||0)-(a[sortCol]||0);});
  }
  var h='';
  for(var i=0;i<hops.length;i++){
    var r=hops[i];
    var c=lc(r.loss_pct);
    var rc=lc(r.recent_loss_pct);
    var flash=r.just_lost?' class="loss-flash"':'';
    h+='<tr'+flash+'>'
      +'<td>'+r.hop+'</td>'
      +'<td><span class="copyable" data-copy="'+(r.hostname!==r.ip?r.hostname:r.ip)+'">'
      +(r.hostname!==r.ip?r.hostname:'\u2014')+'</span></td>'
      +'<td><span class="copyable" data-copy="'+r.ip+'">'+r.ip+'</span></td>'
      +'<td class="'+c+'">'+r.loss_pct.toFixed(1)+'%</td>'
      +'<td class="'+rc+'">'+r.recent_loss_pct.toFixed(1)+'%</td>'
      +'<td class="'+c+'">'+r.loss_count+'</td>'
      +'<td>'+r.sent+'</td>'
      +'<td>'+r.received+'</td>'
      +'<td>'+ms(r.last)+'</td>'
      +'<td>'+ms(r.avg)+'</td>'
      +'<td>'+ms(r.recent_avg)+'</td>'
      +'<td>'+ms(r.jitter)+'</td>'
      +'</tr>';
  }
  document.getElementById('hops').innerHTML=h;

  if(d.chart_data){
    lastChartData=d.chart_data;
    updateChart(d.chart_data);
  }

  var badge=document.getElementById('outageBadge');
  var o='';
  if(!d.outages.length && !d.active_outage){
    o='<span class="none">No notable outages recorded.</span>';
    badge.style.display='none';
  } else {
    badge.style.display=d.active_outage?'inline':'none';
    for(var j=0;j<d.outages.length;j++){
      o+='<div class="evt past">\u25cf '+d.outages[j].fmt+'</div>';
    }
    if(d.active_outage){
      var a=d.active_outage;
      o+='<div class="evt active">\u25b6 '+a.fmt+'</div>';
      for(var k=0;k<a.snapshots.length;k++){
        var s=a.snapshots[k];
        if(s.ip==='*') continue;
        var ib=s.hop===a.bad_hop;
        var host=s.hostname!==s.ip?s.hostname:s.ip;
        var hopLabel=ib?'hop '+(s.hop-1)+' \u2192 '+s.hop:'hop '+s.hop;
        o+='<div class="snap'+(ib?' is-bad':'')+'">';
        o+=(ib?'\u25b8\u25b8 ':'   ')+hopLabel+'  '+host+'  loss '+s.loss_pct.toFixed(1)+'%  avg '+ms(s.avg);
        o+='</div>';
      }
    }
  }
  document.getElementById('outageList').innerHTML=o;
}
es.onmessage=function(e){
  var d=JSON.parse(e.data);
  if(paused){bufferedMsg=d;return;}
  renderData(d);
};
es.onerror=function(){document.getElementById('status').textContent='disconnected \u2013 retrying\u2026';};
syncUI();

// Click-to-copy
document.addEventListener('click',function(e){
  var el=e.target.closest('.copyable');
  if(!el)return;
  var text=el.getAttribute('data-copy');
  if(text && navigator.clipboard){
    navigator.clipboard.writeText(text);
    el.classList.add('copied');
    setTimeout(function(){el.classList.remove('copied');},400);
  }
});
</script>
</body>
</html>
"""


# Send 600s of chart data so all time ranges work client-side
_WEB_CHART_WINDOW = 600


def _build_web_state(
    hops: list[HopStats],
    dest: str,
    tracker: OutageTracker,
    seq: int,
    start_time: float,
) -> str:
    """Serialize current state to JSON for the web dashboard."""
    uptime_s = int(time.monotonic() - start_time)
    m, s = divmod(uptime_s, 60)
    h, m = divmod(m, 60)
    uptime = f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"

    now = time.monotonic()
    cutoff = now - _WEB_CHART_WINDOW

    hop_data = []
    chart_data = []
    for hp in hops:
        hop_data.append(
            {
                "hop": hp.hop,
                "ip": hp.ip,
                "hostname": hp.hostname,
                "loss_pct": hp.loss_pct,
                "recent_loss_pct": hp.recent_loss_pct,
                "loss_count": hp.sent - hp.received,
                "sent": hp.sent,
                "received": hp.received,
                "last": hp.last_ms,
                "avg": hp.avg_ms,
                "recent_avg": hp.recent_avg_ms,
                "jitter": hp.jitter_ms,
                "just_lost": (time.monotonic() - hp._last_loss_time) < 1.5,
            }
        )
        # Build chart data for this hop
        if hp.ip != "*" and hp.history:
            points = []
            loss_x = []
            label = (
                f"{hp.hop}:{hp.hostname}"
                if hp.hostname != hp.ip
                else f"{hp.hop}:{hp.ip}"
            )
            if len(label) > 22:
                label = label[:20] + ".."
            for ts, rtt in hp.history:
                if ts < cutoff:
                    continue
                age = round(ts - now, 2)
                if rtt is not None:
                    points.append((age, round(rtt, 1)))
                else:
                    loss_x.append(age)
            chart_data.append({"label": label, "points": points, "loss": loss_x})

    outages = [{"fmt": e.fmt()} for e in tracker.events[-20:]]

    active = None
    ao = tracker.active_outage
    if ao:
        active = {
            "fmt": ao.fmt(),
            "bad_hop": ao.bad_hop,
            "snapshots": [
                {
                    "hop": s.hop,
                    "ip": s.ip,
                    "hostname": s.hostname,
                    "loss_pct": s.loss_pct,
                    "avg": s.avg_ms,
                }
                for s in ao.hop_snapshots
            ],
        }

    return json.dumps(
        {
            "dest": dest,
            "seq": seq,
            "uptime": uptime,
            "errors": _error_count,
            "hops": hop_data,
            "chart_data": chart_data,
            "outages": outages,
            "active_outage": active,
        }
    )


_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()


def _push_sse(data: str) -> None:
    """Push a state update to all connected SSE clients."""
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                # Drop old data if client is slow
                while not q.empty():
                    try:
                        q.get_nowait()
                    except queue.Empty:
                        break
                q.put_nowait(data)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


class _WebHandler(BaseHTTPRequestHandler):
    """Handles / for the dashboard HTML and /events for SSE stream."""

    def log_message(self, format, *args):  # noqa: A002
        pass  # silence request logs

    def do_GET(self):
        if self.path == "/events":
            self._handle_sse()
        else:
            self._handle_html()

    def _handle_html(self):
        content = _WEB_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q: queue.Queue = queue.Queue(maxsize=4)
        with _sse_lock:
            _sse_clients.append(q)
        try:
            while True:
                try:
                    data = q.get(timeout=30)
                    self.wfile.write(f"data: {data}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    # Keepalive comment
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)


def _start_web_server(
    start_port: int = 9999, max_tries: int = 20
) -> tuple[HTTPServer, int]:
    """Start the web dashboard server in a background daemon thread.

    Tries ports starting from *start_port*, incrementing on failure.
    Returns (server, actual_port).
    """

    class _ThreadingHTTPServer(HTTPServer):
        """HTTPServer that handles each request in a new daemon thread."""

        daemon_threads = True
        allow_reuse_address = True

        def process_request(self, request, client_address):
            t = threading.Thread(
                target=self.process_request_thread,
                args=(request, client_address),
                daemon=True,
            )
            t.start()

        def process_request_thread(self, request, client_address):
            try:
                self.finish_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
            finally:
                self.shutdown_request(request)

    for offset in range(max_tries):
        port = start_port + offset
        try:
            server = _ThreadingHTTPServer(("", port), _WebHandler)
            server.timeout = 1
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            return server, port
        except OSError:
            continue
    raise RuntimeError(
        f"Could not bind to any port in {start_port}-{start_port + max_tries - 1}"
    )


# ─── Main loop ──────────────────────────────────────────────────────────────


async def monitor(
    dest: str,
    interval: float = 0.25,
    max_hops: int = 30,
    web: bool = True,
    web_port: int = 9999,
    show_chart: bool = False,
    loss_threshold: float = 20.0,
    outage_duration: float = 1.0,
    pkt_size: int = 64,
) -> None:
    payload_size = pkt_size - 8  # ICMP header is 8 bytes
    hops = await discover_route(dest, max_hops=max_hops, payload_size=payload_size)
    if not hops:
        Console(stderr=True).print("[bold red]No route discovered.[/]")
        return

    dest_hop = hops[-1]
    tracker = OutageTracker(threshold_pct=loss_threshold, min_duration=outage_duration)
    time_state: dict = {
        "idx": 2,
        "chart": show_chart,
        "help": False,
        "paused": False,
        "sort": "hop",
    }  # start at 60s, chart hidden (press c), help hidden

    # Start web dashboard
    web_url = ""
    web_server = None
    if web:
        web_server, actual_port = _start_web_server(web_port)
        hostname = socket.gethostname()
        web_url = f"http://{hostname}:{actual_port}"
        Console(stderr=True).print(f"[bold cyan]Web dashboard:[/] {web_url}")
    start_time = time.monotonic()

    ident = os.getpid() & 0xFFFF
    seq = 0
    stop = asyncio.Event()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    kb_task = asyncio.create_task(keyboard_listener(stop, time_state))

    console = Console()
    tw, th = console.size
    initial = build_display(
        hops,
        dest,
        tracker,
        TIME_RANGES[time_state["idx"]],
        tw,
        th,
        time_state["chart"],
        show_help=time_state["help"],
        paused=time_state["paused"],
        pkt_size=pkt_size,
        sort_key=time_state["sort"],
        web_url=web_url,
    )

    with Live(initial, console=console, refresh_per_second=4, screen=True) as live:
        while not stop.is_set():
            try:
                seq += 1
                prev_states = [(hop.sent, hop.received) for hop in hops]
                # Track sent for recent stats
                for hop in hops:
                    if hop.ip != "*":
                        hop.record_sent()

                await asyncio.gather(
                    *(
                        ping_hop(hop, ident, seq, payload_size=payload_size)
                        for hop in hops
                    ),
                    return_exceptions=True,
                )

                now_mono = time.monotonic()
                for i, hop in enumerate(hops):
                    _, prev_recv = prev_states[i]
                    if hop.received > prev_recv:
                        hop.history.append((now_mono, hop.last_ms))
                    else:
                        hop.history.append((now_mono, None))
                        if hop.ip != "*":
                            hop.mark_loss()

                # Check for full outage (dest 100% loss) to reset recent counters
                dest_got_reply = dest_hop.received > prev_states[-1][1]
                if not dest_got_reply:
                    all_dest_lost = (
                        all(rtt is None for _, rtt in list(dest_hop.history)[-8:])
                        if len(dest_hop.history) >= 8
                        else False
                    )
                    if all_dest_lost:
                        for hop in hops:
                            hop.reset_recent()

                tracker.record(dest_got_reply, hops=hops)

                # Push to web clients
                if not time_state["paused"]:
                    _push_sse(_build_web_state(hops, dest, tracker, seq, start_time))

                tw, th = console.size
                tr = TIME_RANGES[time_state["idx"]]
                paused = time_state["paused"]
                if not paused or paused != time_state.get("_prev_paused"):
                    live.update(
                        build_display(
                            hops,
                            dest,
                            tracker,
                            tr,
                            tw,
                            th,
                            time_state["chart"],
                            show_help=time_state["help"],
                            paused=paused,
                            pkt_size=pkt_size,
                            sort_key=time_state["sort"],
                            web_url=web_url,
                        )
                    )
                time_state["_prev_paused"] = paused
            except Exception:
                global _error_count
                _error_count += 1

            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass

    kb_task.cancel()
    try:
        await kb_task
    except asyncio.CancelledError:
        pass

    # Shut down web server (in a thread to avoid blocking on SSE clients)
    if web_server is not None:
        shutdown_thread = threading.Thread(target=web_server.shutdown, daemon=True)
        shutdown_thread.start()
        shutdown_thread.join(timeout=2)

    # Final summary to stdout
    console.print("\n[bold]Final statistics:[/]\n")
    console.print(build_table(hops, dest))
    if tracker.events:
        console.print("\n[bold red]Outage events:[/]")
        for evt in tracker.events:
            console.print(f"  ● {evt.fmt_detail()}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="pmtr – network path monitor with charts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Controls:\n  +/=  Increase chart time range\n  -    Decrease chart time range\n  c    Toggle chart\n  q    Quit",
    )
    parser.add_argument(
        "destination",
        nargs="?",
        default="8.8.8.8",
        help="Target host or IP (default: 8.8.8.8)",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=0.25,
        help="Ping interval in seconds (default: 0.25)",
    )
    parser.add_argument(
        "-m",
        "--max-hops",
        type=int,
        default=30,
        help="Maximum TTL / hop count (default: 30)",
    )
    parser.add_argument(
        "-w",
        "--web",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Start web dashboard (default: on, use --no-web to disable)",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=9999,
        help="Starting port for web dashboard (default: 9999, auto-increments if taken)",
    )
    parser.add_argument(
        "-c",
        "--chart",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Show chart on startup (default: off, toggle with 'c' key)",
    )
    parser.add_argument(
        "-l",
        "--loss-threshold",
        type=float,
        default=20.0,
        help="Loss %% threshold to trigger an outage event (default: 20)",
    )
    parser.add_argument(
        "-d",
        "--outage-duration",
        type=float,
        default=1.0,
        help="Minimum duration in seconds to record an outage (default: 1.0)",
    )
    parser.add_argument(
        "-s",
        "--size",
        type=int,
        default=64,
        help="ICMP packet size in bytes including header (default: 64)",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        Console(stderr=True).print(
            "[bold red]This tool requires root privileges for raw ICMP sockets.[/]"
        )
        Console(stderr=True).print("Run with: [bold]sudo uv run pmtr.py[/]")
        sys.exit(1)

    asyncio.run(
        monitor(
            args.destination,
            interval=args.interval,
            max_hops=args.max_hops,
            web=args.web,
            web_port=args.web_port,
            show_chart=args.chart,
            loss_threshold=args.loss_threshold,
            outage_duration=args.outage_duration,
            pkt_size=args.size,
        )
    )


if __name__ == "__main__":
    main()
