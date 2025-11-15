# checkhost-telegram-bot

Distributed uptime & latency monitoring using [check-host.net](https://check-host.net) with a Telegram bot frontend, multi-node checks (HTTP / Ping / TCP), anomaly detection (baseline modeling for RTT / time / loss), and alerts including problematic node details.

---

## Table of Contents

- [What this bot does](#what-this-bot-does)
- [Features](#features)
- [How it works (at a glance)](#how-it-works-at-a-glance)
- [Prerequisites](#prerequisites)
  - [Python](#python)
  - [System packages](#system-packages)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Telegram bot token](#telegram-bot-token)
  - [Allowed Chat IDs](#allowed-chat-ids)
  - [Monitoring targets](#monitoring-targets)
  - [Statistics storage](#statistics-storage)
- [Usage](#usage)
  - [Running the bot](#running-the-bot)
  - [Telegram commands](#telegram-commands)
    - [`/start`](#start)
    - [`/http`](#http)
    - [`/ping`](#ping)
    - [`/tcp`](#tcp)
    - [`/stats`](#stats)
- [Modeling & anomaly detection](#modeling--anomaly-detection)
  - [What is modeled](#what-is-modeled)
  - [Anomaly rules (RTT / time)](#anomaly-rules-rtt--time)
  - [Anomaly rules (packet loss)](#anomaly-rules-packet-loss)
- [Screenshots](#screenshots)
- [Telegram alert examples](#telegram-alert-examples)
  - [Normal ping result](#normal-ping-result)
  - [Loss detected with node info](#loss-detected-with-node-info)
  - [Ping RTT anomaly alert](#ping-rtt-anomaly-alert)
- [Operational notes & hardening](#operational-notes--hardening)
- [Attribution](#attribution)
- [License](#license)

---

## What this bot does

- Periodically checks your targets (HTTP / Ping / TCP) from multiple global nodes via **[check-host.net](https://check-host.net)**.
- Sends **HTML-formatted reports and table images** to one or more Telegram chats.
- Models each node’s **baseline behavior** (RTT / HTTP time / TCP connect time / packet loss) and raises alerts when the current value deviates significantly.
- Includes **node-level metadata** in error cases (HTTP/TCP failures and Ping loss), including a direct `ip-info` link on check-host.net so you can quickly inspect or blacklist problematic monitoring nodes.

---

## Features

- **Multi Chat ID support**
  - `ALLOWED_CHAT_IDS` defines who:
    - can use bot commands
    - will receive auto-monitoring & anomaly alerts
- **Multi-target monitoring**
  - HTTP, Ping, TCP modes, configurable in `CONFIG["targets"]`
- **Baseline modeling**
  - Per `(mode, target, location)` statistics using Welford’s online algorithm
  - Separate models for:
    - HTTP time
    - Ping RTT average
    - Ping loss
    - TCP connect time
- **Anomaly detection**
  - Detects sudden RTT / time spikes
  - Detects when packet loss jumps from “almost zero” to significant
- **Node metadata on failures**
  - When a node has issues:
    - Shows node hostname
    - Adds a direct `ip-info` URL for that node
- **Image reports**
  - Per-check table rendered as PNG using Pillow (HTTP / Ping / TCP)
- **Safe access control**
  - All commands are ignored for non-allowed chats

---

## How it works (at a glance)

1. The bot is started and a background thread launches `auto_monitor()`.
2. On each interval:
   - For each target defined in `CONFIG["targets"]`, the bot calls the appropriate **check-host.net** HTTP API:
     - `/check-http`
     - `/check-ping`
     - `/check-tcp`
   - It polls `/check-result/{request_id}` until node results are available.
   - Builds a detailed HTML summary per node.
   - Renders a PNG table image for the result and sends it to all allowed chat IDs.
   - For each node result, the bot:
     - Updates baseline statistics for time / RTT / loss using Welford’s algorithm.
     - Checks the current value against baseline (z-score + factor thresholds).
     - If anomaly / loss is detected, sends a focused alert including node metadata.
3. The `/stats` command visualizes baselines in a table image (per mode / target / location).

---

## Prerequisites

### Python

- Python **3.9+** is recommended.

### System packages

Install required system packages (example: Debian / Ubuntu):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
sudo apt install -y libjpeg-dev zlib1g-dev  # for Pillow if needed
```

Python dependencies (installed via `pip`):

- `python-telegram-bot`
- `requests`
- `Pillow`

Install them using the bundled requirements file:

```bash
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

*(Adjust versions in `requirements.txt` as needed.)*

---

## Installation

Clone the repository and install dependencies from `requirements.txt`:

```bash
git clone https://github.com/benyaminmansourian/checkhost-telegram-bot.git
cd checkhost-telegram-bot

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

Run the bot script (for example):

```bash
python3 checkhost_monitor.py
```

You can later wrap this in a systemd service or Supervisor configuration for production use.

---

## Configuration

All configuration is done inside the main script (e.g. `checkhost_monitor.py`).

### Telegram bot token

At the top of the script:

```python
BOT_TOKEN = ""   # Telegram Bot token from @BotFather
```

Set it to your bot token:

```python
BOT_TOKEN = "1234567890:ABCDEF..."
```

### Allowed Chat IDs

Only these chats can:

- Use commands: `/start`, `/http`, `/ping`, `/tcp`, `/stats`
- Receive auto-monitoring and anomaly alerts

```python
ALLOWED_CHAT_IDS = [
    "123456789",    # your personal chat ID
    "987654321",    # another admin
]
```

You can add user IDs, group IDs, or channel IDs as needed.

### Monitoring targets

Configured in `CONFIG`:

```python
CONFIG = {
    "interval": 300,   # auto-monitoring interval in seconds (e.g. 300 = 5 minutes)
    "max_nodes": 30,   # max nodes to request from Check-Host
    "targets": [
        {"host": "https://yourdomain.com", "mode": "http"},
        {"host": "yourdomain.com", "mode": "ping"},
        # {"host": "yourdomain.com", "mode": "tcp", "port": 443},
    ]
}
```

Supported `mode` values:

- `"http"` – HTTP check via `check-http`
- `"ping"` – ICMP/ICMP-like via `check-ping`
- `"tcp"` – TCP connect via `check-tcp` (requires a `port` field)

### Statistics storage

Baseline statistics are stored in JSON:

```python
STATS_FILE = "monitor_stats.json"
```

This file is automatically created and updated. You may want to restrict permissions, for example:

```bash
chmod 600 monitor_stats.json
```

---

## Usage

### Running the bot

From your project directory (with virtualenv activated if you use one):

```bash
python3 checkhost_monitor.py
```

You should see something like:

```text
Bot started …
```

Then open a chat with your bot in Telegram (from an **allowed** Chat ID) and send:

```text
/start
```

### Telegram commands

#### `/start`

Shows:

- Auto-monitor interval and configured targets
- Available commands with examples
- `/stats` usage examples

Example output:

```text
🤖 Check-Host Monitoring Bot is running

🔄 Auto monitoring every 5 minutes for:
['https://yourdomain.com', 'yourdomain.com']

Available commands:

🟦 HTTP check
/http https://yourdomain.com

🟧 Ping check
/ping yourdomain.com

🟥 TCP check
/tcp yourdomain.com 443

📊 Baseline statistics (modeling)
/stats
/stats ping
/stats ping yourdomain.com
/stats http https://yourdomain.com
/stats yourdomain.com
```

> If a chat is **not** in `ALLOWED_CHAT_IDS`, `/start` and all other commands are silently ignored.

#### `/http`

Run an HTTP check against a URL:

```text
/http https://yourdomain.com
```

The bot will:

- Call the `check-http` API on check-host.net
- Send an HTML summary
- Send a PNG table with per-node results

#### `/ping`

Run a ping check against a domain / host:

```text
/ping yourdomain.com
```

The bot shows, per node:

- Result: e.g. `4/4 OK`
- RTT (min / avg / max)
- Packet loss (%)
- Target IP
- On packet loss: node hostname + `ip-info` URL on check-host.net

#### `/tcp`

Check TCP connectivity to a host:port:

```text
/tcp yourdomain.com 443
```

The bot shows, per node:

- `Connected` or error message
- Connect time (if successful)
- Target IP
- On errors: node hostname + `ip-info` URL

#### `/stats`

Visualize baselines (RTT / time / loss) as a table image.

Examples:

```text
/stats
```

> Show baselines for all modes and all targets.

```text
/stats ping
```

> Only ping baselines for all monitored targets.

```text
/stats ping yourdomain.com
```

> Ping baselines for a specific target, per location.

```text
/stats http https://yourdomain.com
```

> HTTP time baselines for a specific URL.

```text
/stats yourdomain.com
```

> Baselines (all modes) for a specific target.

If nothing is modeled yet (fresh bot), `/stats` returns:

```text
🚫 No statistics available yet. Let the monitor run for a while.
```

---

## Modeling & anomaly detection

### What is modeled

For each combination of:

- `mode` – `http`, `ping`, `tcp`
- `target` – e.g. `https://yourdomain.com` or `yourdomain.com:443`
- `location` – `"Country, City"` per node

the bot maintains statistics for:

- `time` (HTTP response time)
- `rtt` (Ping average RTT)
- `loss` (Ping packet loss rate)
- `time` (TCP connect time)

All of these are stored in `monitor_stats.json` using **Welford’s online algorithm**:

- `n` – number of samples
- `mean`
- `M2` – aggregate used to compute variance

### Anomaly rules (RTT / time)

RTT / time anomaly is raised when:

- At least `MIN_SAMPLES` are collected (default: `20`)
- Current value is at least `FACTOR_THRESHOLD` × mean (default: `2x`)
- And either:
  - Standard deviation is zero (very stable baseline), or
  - z-score ≥ `SIGMA_THRESHOLD` (default: `3σ`)

Example alert content:

```text
⏱ Current avg RTT: 0.450 s
📊 Previous mean (100 samples): 0.120 s
σ ≈ 0.020 | factor ≈ 3.75x
```

### Anomaly rules (packet loss)

For `loss` (packet loss) the rules are:

- Historical mean loss ≤ `LOSS_BASELINE_MAX` (default: 5%)
- Current loss ≥ `LOSS_ABSOLUTE_THRESHOLD` (default: 10%)

Then a **loss anomaly** is raised.

Otherwise, if loss > 0 but doesn’t meet anomaly criteria, a simpler **"Loss Detected"** alert is sent for visibility.

---

## Screenshots

Example ping report image generated by the bot and sent to Telegram:

```text
Ping Check - google.com

Location              Result   RTT (min/avg/max)   Loss   IP
...
USA, Atlanta          3/4 OK  0.001 / 0.751 / 3.005 s  25.0 %  74.125.21.101
...
```

You can store a real screenshot in the repository and reference it like this:

![Ping check example](https://raw.githubusercontent.com/benyaminmansourian/checkhost-telegram-bot/main/screenshot/ping-google-com.jpg)

Where `screenshot/ping-google-com.jpg` is a sample image similar to:

- Dark theme table
- One row per monitoring node
- Green dots for healthy nodes
- Red rows for nodes with packet loss or high RTT

---

## Telegram alert examples

### Normal ping result

```text
🟢 Germany, Nuremberg
📡 Result: 4/4 OK
⏱ RTT: 0.004 / 0.004 / 0.005 s
📉 Loss: 0.0 %
🧩 IP (target): 172.217.17.84
------------------------------------
```

### Loss detected with node info

```text
🔴 USA, Atlanta
📡 Result: 3/4 OK
⏱ RTT: 0.001 / 0.751 / 3.005 s
📉 Loss: 25.0 %
🧩 IP (target): 74.125.21.101
🛰 Node: us-atlanta-1.node.check-host.net
🔗 Node info: https://check-host.net/ip-info?host=us-atlanta-1.node.check-host.net
------------------------------------
```

You can immediately open the `Node info` URL to see:

- Node IP
- Datacenter
- ISP / ASN

and decide whether the issue is at your server, on the Internet path, or on the monitoring node side.

### Ping RTT anomaly alert

```text
⚠️ Ping RTT Anomaly for `yourdomain.com` at Germany, Nuremberg
⏱ Current avg RTT: 0.450 s
📊 Previous mean (120 samples): 0.120 s
σ ≈ 0.020 | factor ≈ 3.75x

🟢 Germany, Nuremberg
📡 Result: 4/4 OK
⏱ RTT: 0.430 / 0.450 / 0.470 s
📉 Loss: 0.0 %
🧩 IP (target): 172.217.17.84
🛰 Node: de-nuremberg-1.node.check-host.net
🔗 Node info: https://check-host.net/ip-info?host=de-nuremberg-1.node.check-host.net
```

---

## Operational notes & hardening

- Prefer to run the bot under a dedicated system user.
- Restrict permissions on:
  - `monitor_stats.json` (contains performance history)
- Consider:
  - Running it as a systemd service
  - Logging stdout/stderr to journald or a log file
- Respect check-host.net rate limits:
  - Do not set `interval` too low or `max_nodes` too high for many targets.

---

## Attribution

This project uses the public HTTP API provided by **[check-host.net](https://check-host.net)** for all measurements (HTTP, Ping, TCP). All uptime/latency data comes from check-host.net’s distributed monitoring nodes.

---

## License

You can license this project under MIT or any other license you prefer. For example, MIT:

```text
Released under the MIT License. See `LICENSE` for details.
```
