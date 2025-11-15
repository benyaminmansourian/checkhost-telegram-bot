# ==========================================================
# Check-Host Telegram Monitor Bot
# ==========================================================
# Author: Benyamin Mansourian
# GitHub: https://github.com/benyaminmansourian/checkhost-telegram-bot
# License: MIT License
# ==========================================================
# Description:
# A Telegram bot that uses check-host.net to run distributed
# HTTP, Ping, and TCP checks from multiple global nodes and
# sends the results to one or more Telegram chats.
# ==========================================================
# Features:
# - Configurable monitoring targets (HTTP / Ping / TCP)
# - Multi-chat support via ALLOWED_CHAT_IDS
# - Periodic auto-monitoring with detailed HTML reports
# - Per-node baseline modeling (RTT / HTTP time / TCP time / loss)
# - Anomaly detection for spikes and packet loss
# - Node metadata in alerts (node hostname + ip-info link)
# - Table-style result images generated with Pillow
# ==========================================================
# Data source:
# - All measurements are fetched via the public HTTP API
#   of https://check-host.net
# ==========================================================

import requests
import time
import threading
from urllib.parse import quote
import html
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont  # pip install pillow
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import json
import os
import math

# ==============================
#  Bot / Monitoring Settings
# ==============================
BOT_TOKEN = ""   # Telegram Bot token

# List of chats that:
# 1) Are allowed to use commands: /start /http /ping /tcp /stats
# 2) Receive automatic monitoring messages
ALLOWED_CHAT_IDS = [
    "123456789",
    # "987654321",
]

CONFIG = {
    "interval": 600,   # auto-monitoring interval in seconds (e.g. 600 = 10 minutes)
    "max_nodes": 50,   # max nodes to request from Check-Host
    "targets": [
        {"host": "https://yourdomain.com", "mode": "http"},
        {"host": "yourdomain.com", "mode": "ping"},
        # {"host": "yourdomain.com", "mode": "tcp", "port": 443},
    ]
}

CHECKHOST_BASE = "https://check-host.net"
CHECKHOST_RESULT = f"{CHECKHOST_BASE}/check-result/"

STATS_FILE = "monitor_stats.json"

# Minimum number of samples required before anomaly detection
MIN_SAMPLES = 20

# For time/rtt: how many standard deviations above mean is considered anomaly
SIGMA_THRESHOLD = 3.0

# For time/rtt: minimum factor increase over mean to consider anomaly
FACTOR_THRESHOLD = 2.0  # e.g. >= 2x the mean

# For loss: baseline "almost zero" threshold and current anomaly threshold
LOSS_BASELINE_MAX = 0.05        # baseline loss mean <= 5%
LOSS_ABSOLUTE_THRESHOLD = 0.10  # current loss >= 10%


# ==============================
#  Simple Check-Host API wrapper
# ==============================
class ReqApi:
    def reqapi_ch_get_request(self, target: str, method: str, max_nodes: int = 30) -> dict:
        # method: ping, http, tcp
        url = f"{CHECKHOST_BASE}/check-{method}?host={quote(target)}&max_nodes={max_nodes}"
        r = requests.get(url, headers={"Accept": "application/json"}, timeout=15)
        return r.json()

    def reqapi_ch_get_result(self, request_id: str) -> dict:
        url = CHECKHOST_RESULT + str(request_id)
        r = requests.get(url, headers={"Accept": "application/json"}, timeout=15)
        return r.json()


reqapi = ReqApi()


# ==============================
#  Statistics & Modeling
# ==============================
def load_stats():
    if not os.path.exists(STATS_FILE):
        return {}
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_stats(stats):
    try:
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
    except Exception:
        # do not crash the bot because of stats I/O
        pass


STATS = load_stats()
STATS_LOCK = threading.Lock()


def welford_update(metric_stats, value: float):
    n = metric_stats.get("n", 0)
    mean = metric_stats.get("mean", 0.0)
    M2 = metric_stats.get("M2", 0.0)

    n_new = n + 1
    delta = value - mean
    mean_new = mean + delta / n_new
    delta2 = value - mean_new
    M2_new = M2 + delta * delta2

    metric_stats["n"] = n_new
    metric_stats["mean"] = mean_new
    metric_stats["M2"] = M2_new
    return metric_stats


def check_anomaly(metric_stats, value: float, metric_name: str):
    """
    Different anomaly criteria for different metrics:
    - time / rtt: combination of z-score & factor increase
    - loss: baseline almost zero, now significantly higher
    """
    n = metric_stats.get("n", 0)
    mean = metric_stats.get("mean", 0.0)
    M2 = metric_stats.get("M2", 0.0)

    if n < MIN_SAMPLES:
        return False, None

    # Special handling for loss (packet loss in ping)
    if metric_name == "loss":
        # Baseline mean was low (e.g. <= 5%), now loss is high (>= 10%)
        if mean <= LOSS_BASELINE_MAX and value >= LOSS_ABSOLUTE_THRESHOLD:
            if n > 1:
                variance = M2 / (n - 1)
                std = math.sqrt(max(variance, 0.0))
            else:
                std = 0.0

            factor = value / max(mean, 1e-6)
            z_score = (value - mean) / std if std > 0 else None

            return True, {
                "n": n,
                "mean": mean,
                "std": std,
                "factor": factor,
                "z": z_score,
            }
        return False, None

    # time / rtt
    if mean <= 0:
        return False, None

    if n > 1:
        variance = M2 / (n - 1)
        std = math.sqrt(max(variance, 0.0))
    else:
        std = 0.0

    factor = value / mean
    z_score = (value - mean) / std if std > 0 else None

    anomaly = False
    if factor >= FACTOR_THRESHOLD:
        if z_score is None or z_score >= SIGMA_THRESHOLD:
            anomaly = True

    if not anomaly:
        return False, None

    return True, {
        "n": n,
        "mean": mean,
        "std": std,
        "factor": factor,
        "z": z_score,
    }


def update_and_detect(mode: str, target: str, location: str, metric_name: str, value: float):
    """
    mode: 'http' / 'ping' / 'tcp'
    target: e.g. 'https://yourdomain.com' or 'yourdomain.com'
    location: 'Country, City'
    metric_name: 'time' / 'rtt' / 'loss'
    value: new observed value
    """
    global STATS

    with STATS_LOCK:
        STATS.setdefault(mode, {})
        STATS[mode].setdefault(target, {})
        STATS[mode][target].setdefault(location, {})
        metric_stats = STATS[mode][target][location].get(
            metric_name, {"n": 0, "mean": value, "M2": 0.0}
        )

        # Check anomaly against current model
        is_anomaly, details = check_anomaly(metric_stats, value, metric_name)

        # Update model with new value
        metric_stats = welford_update(metric_stats, value)
        STATS[mode][target][location][metric_name] = metric_stats
        save_stats(STATS)

    return is_anomaly, details


def format_metric_stats(metric_name: str, stats: dict) -> str:
    """Pretty-print metrics (for debug / future use)."""
    n = stats.get("n", 0)
    mean = stats.get("mean", 0.0)
    M2 = stats.get("M2", 0.0)
    if n > 1:
        variance = M2 / (n - 1)
        std = math.sqrt(max(variance, 0.0))
    else:
        std = 0.0

    if metric_name == "loss":
        mean_txt = f"{mean * 100:.2f} %"
        std_txt = f"{std * 100:.2f} %"
    else:
        mean_txt = f"{mean:.3f} s"
        std_txt = f"{std:.3f} s"

    return (
        f"    • metric: <code>{html.escape(metric_name)}</code>\n"
        f"      n = <code>{n}</code>, mean = <code>{mean_txt}</code>, σ ≈ <code>{std_txt}</code>\n"
    )


# ==============================
#  HTML Message Splitting Helper
# ==============================
def split_html_message(text: str, max_len: int = 3900):
    lines = text.split("\n")
    chunks = []
    current = ""

    for line in lines:
        add_len = len(line) + (1 if current else 0)
        if len(current) + add_len > max_len:
            if current:
                chunks.append(current)
                current = ""
        if current:
            current += "\n" + line
        else:
            current = line

    if current:
        chunks.append(current)

    return chunks


# ==============================
#  Telegram Helper Functions
# ==============================
def is_allowed_chat_id(chat_id) -> bool:
    if chat_id is None:
        return False
    return str(chat_id) in {str(x) for x in ALLOWED_CHAT_IDS}


async def send_large_async(update: Update, text: str):
    """Send large text in multiple messages in async mode."""
    if not update or not update.message:
        return
    for chunk in split_html_message(text):
        await update.message.reply_text(chunk, parse_mode="HTML")


def telegram_send_sync(text: str):
    """Send text messages synchronously (auto-monitor)."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    for chat_id in ALLOWED_CHAT_IDS:
        for chunk in split_html_message(text):
            requests.post(url, json={
                "chat_id": chat_id,
                "text": chunk,
                "parse_mode": "HTML"
            })


def telegram_send_photo(image_io: BytesIO, caption: str):
    """Send images synchronously (auto-monitor)."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendPhoto"
    files = {
        "photo": ("result.png", image_io.getvalue(), "image/png")
    }
    for chat_id in ALLOWED_CHAT_IDS:
        data = {
            "chat_id": chat_id,
            "caption": caption,
            "parse_mode": "HTML"
        }
        requests.post(url, data=data, files=files)


def send_large_auto(text: str):
    telegram_send_sync(text)


# ==============================
#  Host Cleanup Helper
# ==============================
def clean_host_for_ping(url_or_host: str) -> str:
    """Strip protocol and path, keep only hostname."""
    h = url_or_host.strip()
    if h.startswith("http://") or h.startswith("https://"):
        h = h.split("://", 1)[1]
    return h.split("/", 1)[0]


# ==============================
#  Poll Check-Host results with retries
# ==============================
def wait_for_result(request_id: str, expected_nodes: int, retries: int = 10, delay: float = 2.0) -> dict:
    """
    Call /check-result multiple times until:
    - we have data for all expected nodes, or
    - we run out of retries.
    """
    last_data = {}
    for attempt in range(retries):
        data = reqapi.reqapi_ch_get_result(request_id)
        last_data = data

        if not isinstance(data, dict):
            time.sleep(delay)
            continue

        if len(data) == 0:
            time.sleep(delay)
            continue

        if len(data) >= expected_nodes:
            if all(v is not None for v in data.values()):
                break
            non_null = sum(1 for v in data.values() if v is not None)
            if non_null > 0 and attempt >= retries - 2:
                break

        time.sleep(delay)

    return last_data


# ==============================
#  Image Rendering Helpers
# ==============================
def get_font(size=14):
    try:
        return ImageFont.truetype("arial.ttf", size)
    except Exception:
        return ImageFont.load_default()


def render_table_image(title: str, columns, keys, rows):
    """
    columns: list of column titles
    keys: key names used in row dicts
    rows: list of dicts, each with keys + 'ok' (True/False)
    """
    padding_x = 20
    padding_y = 20
    row_height = 28
    header_height = 32

    col_count = len(columns)
    col_width = 170
    width = padding_x * 2 + col_count * col_width
    height = padding_y * 2 + 30 + header_height + len(rows) * row_height + 20

    img = Image.new("RGB", (width, height), (24, 24, 24))
    draw = ImageDraw.Draw(img)

    font_title = get_font(18)
    font_header = get_font(14)
    font_cell = get_font(13)

    # Title
    draw.text(
        (padding_x, padding_y),
        title,
        font=font_title,
        fill=(255, 255, 255)
    )

    table_top = padding_y + 30
    table_left = padding_x
    table_right = width - padding_x

    # Header background
    draw.rectangle(
        [table_left, table_top, table_right, table_top + header_height],
        fill=(50, 50, 50)
    )

    # Header text
    for idx, col_name in enumerate(columns):
        x = table_left + idx * col_width + 10
        y = table_top + 8
        draw.text((x, y), col_name, font=font_header, fill=(230, 230, 230))

    # Header lines
    draw.line(
        [table_left, table_top, table_right, table_top],
        fill=(80, 80, 80),
        width=1
    )
    draw.line(
        [table_left, table_top + header_height, table_right, table_top + header_height],
        fill=(80, 80, 80),
        width=1
    )

    # Rows
    start_y = table_top + header_height
    for row_idx, row in enumerate(rows):
        y = start_y + row_idx * row_height
        bg_color = (30, 30, 30) if row.get("ok", False) else (40, 28, 28)
        draw.rectangle(
            [table_left, y, table_right, y + row_height],
            fill=bg_color
        )

        # Status circle
        circle_x = table_left + 8
        circle_y = y + row_height / 2
        color = (76, 175, 80) if row.get("ok", False) else (244, 67, 54)
        draw.ellipse(
            [circle_x - 5, circle_y - 5, circle_x + 5, circle_y + 5],
            fill=color
        )

        # Cell text
        for c_idx, key in enumerate(keys):
            text = str(row.get(key, ""))
            x = table_left + c_idx * col_width + (20 if c_idx == 0 else 10)
            ty = y + 7
            draw.text((x, ty), text, font=font_cell, fill=(230, 230, 230))

        # Row separator
        draw.line(
            [table_left, y + row_height, table_right, y + row_height],
            fill=(60, 60, 60),
            width=1
        )

    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def render_http_image(domain: str, rows):
    title = f"HTTP Check - {domain}"
    columns = ["Location", "Result", "Time", "Code", "IP"]
    keys = ["location", "result", "time", "code", "ip"]
    return render_table_image(title, columns, keys, rows)


def render_ping_image(domain: str, rows):
    title = f"Ping Check - {domain}"
    columns = ["Location", "Result", "RTT", "Loss", "IP"]
    keys = ["location", "result", "rtt", "loss", "ip"]
    return render_table_image(title, columns, keys, rows)


def render_tcp_image(target: str, rows):
    title = f"TCP Check - {target}"
    columns = ["Location", "Result", "Time", "IP"]
    keys = ["location", "result", "time", "ip"]
    return render_table_image(title, columns, keys, rows)


def build_stats_rows(stats_snapshot, mode_filter=None, target_filter=None, max_rows=80):
    """
    Build flattened rows for stats table image.
    Each row: Mode, Target, Location, Metric, Mean, Std Dev, N
    """
    rows = []
    for mode, targets in stats_snapshot.items():
        if mode_filter and mode != mode_filter:
            continue
        for target, locations in targets.items():
            if target_filter and target != target_filter:
                continue
            for location, metrics in locations.items():
                for metric_name, metric_stats in metrics.items():
                    n = metric_stats.get("n", 0)
                    mean = metric_stats.get("mean", 0.0)
                    M2 = metric_stats.get("M2", 0.0)
                    if n > 1:
                        variance = M2 / (n - 1)
                        std = math.sqrt(max(variance, 0.0))
                    else:
                        std = 0.0

                    if metric_name == "loss":
                        mean_txt = f"{mean * 100:.2f} %"
                        std_txt = f"{std * 100:.2f} %"
                    else:
                        mean_txt = f"{mean:.3f} s"
                        std_txt = f"{std:.3f} s"

                    rows.append({
                        "mode": mode,
                        "target": target,
                        "location": location,
                        "metric": metric_name,
                        "mean": mean_txt,
                        "std": std_txt,
                        "n": str(n),
                        "ok": True,
                    })

                    if len(rows) >= max_rows:
                        return rows
    return rows


def render_stats_image(stats_snapshot, mode_filter=None, target_filter=None):
    rows = build_stats_rows(stats_snapshot, mode_filter, target_filter)
    if not rows:
        return None
    title = "Baseline Statistics"
    columns = ["Mode", "Target", "Location", "Metric", "Mean", "Std Dev", "N"]
    keys = ["mode", "target", "location", "metric", "mean", "std", "n"]
    return render_table_image(title, columns, keys, rows)


# ==============================
#  HTTP CHECK (text + rows)
# ==============================
def http_check(domain: str, max_nodes: int):
    req = reqapi.reqapi_ch_get_request(domain, "http", max_nodes)
    if not req.get("request_id"):
        return "❌ Error in HTTP request (API limit or error).", []

    request_id = req["request_id"]
    nodes = req.get("nodes", {})
    res = wait_for_result(request_id, expected_nodes=len(nodes))

    msg = f"🔍 <b>HTTP Check</b>: <code>{html.escape(domain)}</code>\n\n"
    node_count = 0
    rows = []

    for node_name, node_info in nodes.items():
        # node_info: [code, country, city, ...] (we only use country/city)
        country = node_info[1] if len(node_info) > 1 else "-"
        city = node_info[2] if len(node_info) > 2 else "-"

        node_result = res.get(node_name)
        if node_result is None or node_result == [] or node_result == [None]:
            continue

        # Expected format: [[success, time, status_text, http_code, ip]]
        entry = node_result[0] if node_result else None
        if not entry:
            continue

        node_count += 1

        success_flag = entry[0] if len(entry) > 0 else None
        time_sec = entry[1] if len(entry) > 1 else None
        status_text = entry[2] if len(entry) > 2 else "-"
        http_code = entry[3] if len(entry) > 3 else "-"
        ip = entry[4] if len(entry) > 4 else "-"

        emoji = "🟢" if success_flag == 1 else "🔴"

        msg += f"{emoji} <b>{html.escape(country)}, {html.escape(city)}</b>\n"
        msg += f"📡 Result: <code>{html.escape(str(status_text))}</code>\n"
        if time_sec is not None:
            msg += f"⏱ Time: <code>{time_sec:.3f} s</code>\n"
        msg += f"📄 Code: <code>{html.escape(str(http_code))}</code>\n"
        msg += f"🧩 IP (target): <code>{html.escape(str(ip))}</code>\n"
        # Node info only when this node has an HTTP error
        if success_flag != 1:
            msg += f"🛰 Node: <code>{html.escape(node_name)}</code>\n"
            msg += (
                "🔗 Node info: "
                f"<code>https://check-host.net/ip-info?host={html.escape(node_name)}</code>\n"
            )
        msg += "------------------------------------\n"

        rows.append({
            "location": f"{country}, {city}",
            "result": str(status_text),
            "time": f"{time_sec:.3f} s" if time_sec is not None else "-",
            "time_value": float(time_sec) if time_sec is not None else None,
            "code": str(http_code),
            "ip": str(ip),
            "node": node_name,
            "ok": (success_flag == 1),
        })

    if node_count == 0:
        return (
            f"🔍 <b>HTTP Check</b>: <code>{html.escape(domain)}</code>\n\n"
            f"❌ No node returned a result.",
            []
        )

    return msg, rows


# ==============================
#  PING CHECK (text + rows)
# ==============================
def ping_check(domain: str, max_nodes: int):
    req = reqapi.reqapi_ch_get_request(domain, "ping", max_nodes)
    if not req.get("request_id"):
        return "❌ Error in Ping request (API limit or error).", []

    request_id = req["request_id"]
    nodes = req.get("nodes", {})
    res = wait_for_result(request_id, expected_nodes=len(nodes))

    msg = f"🔍 <b>Ping Check</b>: <code>{html.escape(domain)}</code>\n\n"
    node_count = 0
    rows = []

    for node_name, node_info in nodes.items():
        # node_info: [code, country, city, ...]
        country = node_info[1] if len(node_info) > 1 else "-"
        city = node_info[2] if len(node_info) > 2 else "-"

        node_result = res.get(node_name)
        if node_result is None or node_result == [] or node_result == [None]:
            continue

        attempts = node_result[0] if node_result else []
        if not attempts:
            continue

        total = len(attempts)
        ok_count = 0
        times = []
        ip = "-"

        for att in attempts:
            if not att:
                continue
            status = att[0] if len(att) > 0 else "-"
            t = att[1] if len(att) > 1 else None
            if len(att) > 2 and att[2]:
                ip = att[2]
            if status == "OK":
                ok_count += 1
            if isinstance(t, (int, float)):
                times.append(t)

        if times:
            t_min = min(times)
            t_avg = sum(times) / len(times)
            t_max = max(times)
            rtt_summary = f"{t_min:.3f} / {t_avg:.3f} / {t_max:.3f} s"
        else:
            t_avg = None
            rtt_summary = "-"

        result_summary = f"{ok_count}/{total} OK"
        loss_rate = (total - ok_count) / total if total > 0 else None
        loss_text = f"{loss_rate * 100:.1f} %" if loss_rate is not None else "-"

        ok_flag = (total > 0 and ok_count == total)
        emoji = "🟢" if ok_flag else "🔴"

        node_count += 1

        msg += f"{emoji} <b>{html.escape(country)}, {html.escape(city)}</b>\n"
        msg += f"📡 Result: <code>{html.escape(result_summary)}</code>\n"
        msg += f"⏱ RTT: <code>{html.escape(rtt_summary)}</code>\n"
        msg += f"📉 Loss: <code>{html.escape(loss_text)}</code>\n"
        msg += f"🧩 IP (target): <code>{html.escape(str(ip))}</code>\n"
        # Node info only when there is packet loss
        if loss_rate is not None and loss_rate > 0.0:
            msg += f"🛰 Node: <code>{html.escape(node_name)}</code>\n"
            msg += (
                "🔗 Node info: "
                f"<code>https://check-host.net/ip-info?host={html.escape(node_name)}</code>\n"
            )
        msg += "------------------------------------\n"

        rows.append({
            "location": f"{country}, {city}",
            "result": result_summary,
            "rtt": rtt_summary,
            "rtt_avg_value": float(t_avg) if t_avg is not None else None,
            "loss": loss_text,
            "loss_rate": float(loss_rate) if loss_rate is not None else None,
            "ip": str(ip),          # target IP
            "node": node_name,      # node hostname
            "ok": ok_flag,
        })

    if node_count == 0:
        return (
            f"🔍 <b>Ping Check</b>: <code>{html.escape(domain)}</code>\n\n"
            f"❌ No node returned a result.",
            []
        )

    return msg, rows


# ==============================
#  TCP CHECK (text + rows)
# ==============================
def tcp_check(domain: str, port: str, max_nodes: int):
    target = f"{domain}:{port}"
    req = reqapi.reqapi_ch_get_request(target, "tcp", max_nodes)
    if not req.get("request_id"):
        return "❌ Error in TCP request (API limit or error).", [], target

    request_id = req["request_id"]
    nodes = req.get("nodes", {})
    res = wait_for_result(request_id, expected_nodes=len(nodes))

    msg = f"🔍 <b>TCP Check</b>: <code>{html.escape(target)}</code>\n\n"
    node_count = 0
    rows = []

    for node_name, node_info in nodes.items():
        # node_info: [code, country, city, ...]
        country = node_info[1] if len(node_info) > 1 else "-"
        city = node_info[2] if len(node_info) > 2 else "-"

        node_result = res.get(node_name)
        if node_result is None or node_result == [] or node_result == [None]:
            continue

        entry = node_result[0] if node_result else {}
        time_sec = entry.get("time")
        address = entry.get("address")
        error = entry.get("error")

        if time_sec is not None:
            result_text = "Connected"
            ip = address or "-"
            ok_flag = True
        else:
            result_text = error or "Error"
            ip = "-"
            ok_flag = False

        node_count += 1

        msg += f"{'🟢' if ok_flag else '🔴'} <b>{html.escape(country)}, {html.escape(city)}</b>\n"
        msg += f"📡 Result: <code>{html.escape(str(result_text))}</code>\n"
        if time_sec is not None:
            msg += f"⏱ Time: <code>{time_sec:.3f} s</code>\n"
        msg += f"🧩 IP (target): <code>{html.escape(str(ip))}</code>\n"
        # Node info only when TCP is not connected
        if not ok_flag:
            msg += f"🛰 Node: <code>{html.escape(node_name)}</code>\n"
            msg += (
                "🔗 Node info: "
                f"<code>https://check-host.net/ip-info?host={html.escape(node_name)}</code>\n"
            )
        msg += "------------------------------------\n"

        rows.append({
            "location": f"{country}, {city}",
            "result": str(result_text),
            "time": f"{time_sec:.3f} s" if time_sec is not None else "-",
            "time_value": float(time_sec) if time_sec is not None else None,
            "ip": str(ip),          # target IP
            "node": node_name,
            "ok": ok_flag,
        })

    if node_count == 0:
        return (
            f"🔍 <b>TCP Check</b>: <code>{html.escape(target)}</code>\n\n"
            f"❌ No node returned a result.",
            [],
            target
        )

    return msg, rows, target


# ==============================
#  Telegram Commands
# ==============================
async def start_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id if update.effective_chat else None
    if not is_allowed_chat_id(chat_id):
        return

    targets = [t["host"] for t in CONFIG["targets"]]
    primary = targets[0] if targets else "https://yourdomain.com"
    clean = clean_host_for_ping(primary)

    txt = f"""
🤖 Check-Host Monitoring Bot is running

🔄 Auto monitoring every {CONFIG['interval'] // 60} minutes for:
<code>{html.escape(str(targets))}</code>

Available commands:

🟦 HTTP check
<code>/http {html.escape(primary)}</code>
- Check HTTP status and response time from multiple nodes.

🟧 Ping check
<code>/ping {html.escape(clean)}</code>
- Multi-node ping, shows RTT (min/avg/max), packet loss and target IP.

🟥 TCP check
<code>/tcp {html.escape(clean)} 443</code>
- TCP connect time to the given host:port from multiple nodes.

📊 Baseline statistics (modeling)
<code>/stats</code>
- Show baseline stats (time / RTT / loss) for all modes and targets.

<code>/stats ping</code>
- Only ping baselines for all monitored targets.

<code>/stats ping {html.escape(clean)}</code>
- Ping baselines for a specific target (per location).

<code>/stats http {html.escape(primary)}</code>
- HTTP baselines for a specific URL.

<code>/stats {html.escape(clean)}</code>
- Baselines (all modes) for a specific target.

ℹ️ Notes:
- Only chat IDs in <code>ALLOWED_CHAT_IDS</code> can use commands and receive auto-monitoring messages.
- The bot automatically models time/RTT/loss and raises anomalies if values change significantly.
"""
    await update.message.reply_text(txt.strip(), parse_mode="HTML")


async def http_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id if update.effective_chat else None
    if not is_allowed_chat_id(chat_id):
        return

    if not ctx.args:
        await update.message.reply_text(
            "Example:\n<code>/http https://yourdomain.com</code>",
            parse_mode="HTML"
        )
        return

    domain = ctx.args[0]
    msg, rows = http_check(domain, CONFIG["max_nodes"])
    await send_large_async(update, msg)
    if rows:
        img = render_http_image(domain, rows)
        await update.message.reply_photo(
            photo=img,
            caption=f"📊 <b>HTTP Result</b>: <code>{html.escape(domain)}</code>",
            parse_mode="HTML"
        )


async def ping_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id if update.effective_chat else None
    if not is_allowed_chat_id(chat_id):
        return

    if not ctx.args:
        await update.message.reply_text(
            "Example:\n<code>/ping yourdomain.com</code>",
            parse_mode="HTML"
        )
        return

    domain = ctx.args[0]
    msg, rows = ping_check(domain, CONFIG["max_nodes"])
    await send_large_async(update, msg)
    if rows:
        img = render_ping_image(domain, rows)
        await update.message.reply_photo(
            photo=img,
            caption=f"📊 <b>Ping Result</b>: <code>{html.escape(domain)}</code>",
            parse_mode="HTML"
        )


async def tcp_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id if update.effective_chat else None
    if not is_allowed_chat_id(chat_id):
        return

    if len(ctx.args) < 2:
        await update.message.reply_text(
            "Example:\n<code>/tcp yourdomain.com 443</code>",
            parse_mode="HTML"
        )
        return

    domain = ctx.args[0]
    port = ctx.args[1]
    msg, rows, target = tcp_check(domain, port, CONFIG["max_nodes"])
    await send_large_async(update, msg)
    if rows:
        img = render_tcp_image(target, rows)
        await update.message.reply_photo(
            photo=img,
            caption=f"📊 <b>TCP Result</b>: <code>{html.escape(target)}</code>",
            parse_mode="HTML"
        )


async def stats_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """
    /stats
    /stats ping
    /stats ping yourdomain.com
    /stats http https://yourdomain.com
    /stats yourdomain.com
    """
    chat_id = update.effective_chat.id if update.effective_chat else None
    if not is_allowed_chat_id(chat_id):
        return

    mode_filter = None
    target_filter = None

    if ctx.args:
        first = ctx.args[0].lower()
        if first in ("http", "ping", "tcp"):
            mode_filter = first
            if len(ctx.args) >= 2:
                target_filter = ctx.args[1]
        else:
            target_filter = ctx.args[0]

    with STATS_LOCK:
        stats_snapshot = json.loads(json.dumps(STATS))

    if not stats_snapshot:
        await send_large_async(
            update,
            "🚫 No statistics available yet. Let the monitor run for a while."
        )
        return

    img = render_stats_image(stats_snapshot, mode_filter, target_filter)
    if img is None:
        await send_large_async(
            update,
            "🚫 No statistics found for this filter."
        )
        return

    filter_desc = []
    if mode_filter:
        filter_desc.append(f"mode={mode_filter}")
    if target_filter:
        filter_desc.append(f"target={target_filter}")
    filter_text = " | ".join(filter_desc) if filter_desc else "all modes & targets"

    await update.message.reply_photo(
        photo=img,
        caption=f"📊 <b>Baseline Statistics</b>\n<code>{html.escape(filter_text)}</code>",
        parse_mode="HTML"
    )


# ==============================
#  Auto Monitoring Loop
# ==============================
def auto_monitor():
    while True:
        for target in CONFIG["targets"]:
            host = target["host"]
            mode = target["mode"]

            try:
                if mode == "http":
                    msg, rows = http_check(host, CONFIG["max_nodes"])
                    prefix = "🟢 <b>HTTP Monitor</b>"
                    send_large_auto(f"{prefix}\n\n{msg}")

                    alerts = []
                    for row in rows:
                        if not row.get("ok"):
                            # optional: you can also add pure "HTTP error" alerts here
                            continue
                        value = row.get("time_value")
                        if value is None:
                            continue

                        node_block = (
                            f"{'🟢' if row.get('ok') else '🔴'} "
                            f"<b>{html.escape(row['location'])}</b>\n"
                            f"📡 Result: <code>{html.escape(row['result'])}</code>\n"
                            f"⏱ Time: <code>{html.escape(row['time'])}</code>\n"
                            f"📄 Code: <code>{html.escape(row['code'])}</code>\n"
                            f"🧩 IP (target): <code>{html.escape(row['ip'])}</code>\n"
                            f"🛰 Node: <code>{html.escape(row['node'])}</code>\n"
                            "🔗 Node info: "
                            f"<code>https://check-host.net/ip-info?host={html.escape(row['node'])}</code>\n"
                        )

                        is_anomaly, details = update_and_detect(
                            mode="http",
                            target=host,
                            location=row["location"],
                            metric_name="time",
                            value=value,
                        )
                        if is_anomaly and details:
                            alerts.append(
                                f"⚠️ <b>HTTP Anomaly</b> for <code>{html.escape(host)}</code> at "
                                f"<b>{html.escape(row['location'])}</b>\n"
                                f"⏱ Current: <code>{value:.3f} s</code>\n"
                                f"📊 Previous mean ({details['n']} samples): "
                                f"<code>{details['mean']:.3f} s</code>\n"
                                f"σ ≈ <code>{details['std']:.3f}</code> | "
                                f"factor ≈ <code>{details['factor']:.2f}x</code>\n\n"
                                f"{node_block}"
                            )

                    if alerts:
                        send_large_auto("\n\n".join(alerts))

                    if rows:
                        img = render_http_image(host, rows)
                        telegram_send_photo(
                            img,
                            caption=f"{prefix}\n🔍 <b>HTTP Check</b>: <code>{html.escape(host)}</code>"
                        )

                elif mode == "ping":
                    d = clean_host_for_ping(host)
                    msg, rows = ping_check(d, CONFIG["max_nodes"])
                    prefix = "🟢 <b>Ping Monitor</b>"
                    send_large_auto(f"{prefix}\n\n{msg}")

                    alerts = []
                    for row in rows:
                        node_block = (
                            f"{'🟢' if row.get('ok') else '🔴'} "
                            f"<b>{html.escape(row['location'])}</b>\n"
                            f"📡 Result: <code>{html.escape(row['result'])}</code>\n"
                            f"⏱ RTT: <code>{html.escape(row['rtt'])}</code>\n"
                            f"📉 Loss: <code>{html.escape(row['loss'])}</code>\n"
                            f"🧩 IP (target): <code>{html.escape(row['ip'])}</code>\n"
                            f"🛰 Node: <code>{html.escape(row['node'])}</code>\n"
                            "🔗 Node info: "
                            f"<code>https://check-host.net/ip-info?host={html.escape(row['node'])}</code>\n"
                        )

                        # RTT anomaly (only for "ok" nodes with valid RTT average)
                        rtt_value = row.get("rtt_avg_value")
                        if rtt_value is not None and row.get("ok"):
                            is_anomaly_rtt, details_rtt = update_and_detect(
                                mode="ping",
                                target=d,
                                location=row["location"],
                                metric_name="rtt",
                                value=rtt_value,
                            )
                            if is_anomaly_rtt and details_rtt:
                                alerts.append(
                                    f"⚠️ <b>Ping RTT Anomaly</b> for <code>{html.escape(d)}</code> at "
                                    f"<b>{html.escape(row['location'])}</b>\n"
                                    f"⏱ Current avg RTT: <code>{rtt_value:.3f} s</code>\n"
                                    f"📊 Previous mean ({details_rtt['n']} samples): "
                                    f"<code>{details_rtt['mean']:.3f} s</code>\n"
                                    f"σ ≈ <code>{details_rtt['std']:.3f}</code> | "
                                    f"factor ≈ <code>{details_rtt['factor']:.2f}x</code>\n\n"
                                    f"{node_block}"
                                )

                        # Packet Loss anomaly / detection
                        loss_rate = row.get("loss_rate")
                        if loss_rate is not None:
                            is_anomaly_loss, details_loss = update_and_detect(
                                mode="ping",
                                target=d,
                                location=row["location"],
                                metric_name="loss",
                                value=loss_rate,
                            )

                            if is_anomaly_loss and details_loss:
                                alerts.append(
                                    f"⚠️ <b>Ping Loss Anomaly</b> for "
                                    f"<code>{html.escape(d)}</code> at "
                                    f"<b>{html.escape(row['location'])}</b>\n"
                                    f"📉 Current loss: <code>{loss_rate * 100:.1f} %</code>\n"
                                    f"📊 Previous mean loss ({details_loss['n']} samples): "
                                    f"<code>{details_loss['mean'] * 100:.2f} %</code>\n\n"
                                    f"{node_block}"
                                )
                            elif loss_rate > 0.0:
                                alerts.append(
                                    f"⚠️ <b>Ping Loss Detected</b> for "
                                    f"<code>{html.escape(d)}</code> at "
                                    f"<b>{html.escape(row['location'])}</b>\n"
                                    f"📉 Loss: <code>{loss_rate * 100:.1f} %</code>\n\n"
                                    f"{node_block}"
                                )

                    if alerts:
                        send_large_auto("\n\n".join(alerts))

                    if rows:
                        img = render_ping_image(d, rows)
                        telegram_send_photo(
                            img,
                            caption=f"{prefix}\n🔍 <b>Ping Check</b>: <code>{html.escape(d)}</code>"
                        )

                elif mode == "tcp":
                    d = clean_host_for_ping(host)
                    port = str(target.get("port", 443))
                    msg, rows, tcp_target = tcp_check(d, port, CONFIG["max_nodes"])
                    prefix = f"🟢 <b>TCP Monitor {html.escape(port)}</b>"
                    send_large_auto(f"{prefix}\n\n{msg}")

                    alerts = []
                    for row in rows:
                        if not row.get("ok"):
                            # also could alert on raw TCP errors if you want
                            continue
                        value = row.get("time_value")
                        if value is None:
                            continue

                        node_block = (
                            f"{'🟢' if row.get('ok') else '🔴'} "
                            f"<b>{html.escape(row['location'])}</b>\n"
                            f"📡 Result: <code>{html.escape(row['result'])}</code>\n"
                            f"⏱ Time: <code>{html.escape(row['time'])}</code>\n"
                            f"🧩 IP (target): <code>{html.escape(row['ip'])}</code>\n"
                            f"🛰 Node: <code>{html.escape(row['node'])}</code>\n"
                            "🔗 Node info: "
                            f"<code>https://check-host.net/ip-info?host={html.escape(row['node'])}</code>\n"
                        )

                        is_anomaly, details = update_and_detect(
                            mode="tcp",
                            target=tcp_target,
                            location=row["location"],
                            metric_name="time",
                            value=value,
                        )
                        if is_anomaly and details:
                            alerts.append(
                                f"⚠️ <b>TCP Anomaly</b> for <code>{html.escape(tcp_target)}</code> at "
                                f"<b>{html.escape(row['location'])}</b>\n"
                                f"⏱ Current connect time: <code>{value:.3f} s</code>\n"
                                f"📊 Previous mean ({details['n']} samples): "
                                f"<code>{details['mean']:.3f} s</code>\n"
                                f"σ ≈ <code>{details['std']:.3f}</code> | "
                                f"factor ≈ <code>{details['factor']:.2f}x</code>\n\n"
                                f"{node_block}"
                            )

                    if alerts:
                        send_large_auto("\n\n".join(alerts))

                    if rows:
                        img = render_tcp_image(tcp_target, rows)
                        telegram_send_photo(
                            img,
                            caption=f"{prefix}\n🔍 <b>TCP Check</b>: <code>{html.escape(tcp_target)}</code>"
                        )

            except Exception as e:
                send_large_auto(
                    f"❌ Error in monitoring {html.escape(host)} ({html.escape(mode)}):\n"
                    f"{html.escape(str(e))}"
                )

        time.sleep(CONFIG["interval"])


# ==============================
#  Main
# ==============================
def main():
    threading.Thread(target=auto_monitor, daemon=True).start()

    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("http", http_cmd))
    app.add_handler(CommandHandler("ping", ping_cmd))
    app.add_handler(CommandHandler("tcp", tcp_cmd))
    app.add_handler(CommandHandler("stats", stats_cmd))

    print("Bot started …")
    app.run_polling()


if __name__ == "__main__":
    main()


