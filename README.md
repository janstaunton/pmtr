# pmtr

A lightweight, real-time network path monitor — like [MTR](https://www.bitwizard.nl/mtr/), but with live latency charts, an outage tracker, and a built-in web dashboard.

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

## Motivation

Standard tools like `ping` and `traceroute` give you a snapshot, but when packet loss is intermittent you need to watch the entire path over hours — or days — to catch where it's happening. pmtr was built to leave running in the background and continuously monitor every hop, so you can pinpoint exactly which link degrades and when.

Publishing this is mostly an effort to amortise the token cost of generating it — if someone else finds it useful, all the better.

## Features

- **Traceroute + continuous ping** — discovers every hop to the destination, then monitors them all in parallel
- **Rich terminal UI** — colour-coded loss/latency table with real-time updates via [Rich](https://github.com/Textualize/rich)
- **Latency charts** — inline ASCII charts powered by [plotext](https://github.com/piccolomo/plotext), adjustable from 15 s to 10 min
- **Web dashboard** — a self-contained HTML dashboard served over HTTP with live Chart.js graphs and Server-Sent Events; works from any browser on the network
- **Outage detection** — automatically flags periods of sustained packet loss, identifies the first "bad hop", and logs events with per-hop snapshots
- **Recent-stats reset** — counters reset after a full outage so you can see post-recovery health at a glance
- **Custom packet sizes** — test with jumbo frames or specific MTU sizes
- **Keyboard-driven** — sort columns, toggle the chart, pause updates, and adjust the time window without leaving the terminal
- **Zero config** — single-file script, no install step; just `uv run` and go

## Requirements

- **Python 3.11+**
- **Root / sudo** — required for raw ICMP sockets
- [**uv**](https://github.com/astral-sh/uv) (recommended) — handles dependencies automatically via the inline script metadata

## Quick Start

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Run (uv resolves dependencies automatically)
sudo uv run pmtr.py 8.8.8.8
```

## Usage

```
sudo uv run pmtr.py [destination] [options]
```

| Option | Default | Description |
|---|---|---|
| `destination` | `8.8.8.8` | Target host or IP address |
| `-i`, `--interval` | `0.25` | Ping interval in seconds |
| `-m`, `--max-hops` | `30` | Maximum TTL / hop count |
| `-s`, `--size` | `64` | ICMP packet size in bytes (including header) |
| `-c`, `--chart` / `--no-chart` | off | Show the terminal chart on startup |
| `-w`, `--web` / `--no-web` | on | Start the web dashboard |
| `--web-port` | `9999` | Starting port for the web dashboard (auto-increments if taken) |
| `-l`, `--loss-threshold` | `20.0` | Loss % to trigger an outage event |
| `-d`, `--outage-duration` | `1.0` | Minimum seconds to record an outage |

### Examples

```bash
# Monitor Cloudflare DNS with 0.5 s interval
sudo uv run pmtr.py 1.1.1.1 --interval 0.5

# Test path MTU with large packets, no web dashboard
sudo uv run pmtr.py 8.8.8.8 --size 1400 --no-web

# Lower outage sensitivity
sudo uv run pmtr.py example.com --loss-threshold 50 --outage-duration 5
```

## Keyboard Controls

| Key | Action |
|---|---|
| `+` / `=` | Increase chart time range |
| `-` | Decrease chart time range |
| `c` | Toggle latency chart |
| `p` | Pause display updates |
| `s` | Cycle sort column (hop → loss% → avg → last → jitter) |
| `?` | Show / hide help panel |
| `q` | Quit |

## Web Dashboard

By default, pmtr starts an HTTP server on port **9999** (or the next available port). Open the URL printed at startup in any browser to get:

- Live hop table with sortable columns and click-to-copy hostnames/IPs
- Interactive Chart.js latency graph with adjustable time window
- Outage log with bad-hop identification
- Keyboard shortcuts work in the browser too

The dashboard uses **Server-Sent Events** for real-time updates with automatic reconnection.

## Table Columns

| Column | Description |
|---|---|
| **Loss%** | Overall packet loss since start |
| **Rcnt%** | Loss since the last full outage (counters reset automatically) |
| **Loss** | Total lost packet count |
| **Last** | Most recent round-trip time |
| **Avg** | Average RTT since start |
| **RAvg** | Average RTT since last full outage |
| **Jtr** | Jitter — standard deviation of recent RTT samples |

## Linting

```bash
uv tool run ruff check pmtr.py
uv run --with pyright --with plotext pyright pmtr.py
```

## Credits

This project was entirely AI-generated using Claude (Opus) and Gemini.

## Disclaimer

> **⚠️ This code has not been human-reviewed.** It was generated entirely by AI (Claude Opus and Gemini) and is provided as-is with no warranties of any kind. Use it at your own risk. The tool requires root privileges and opens raw ICMP sockets — you should understand what that means before running it on any system you care about.

## License

[MIT](LICENSE)
