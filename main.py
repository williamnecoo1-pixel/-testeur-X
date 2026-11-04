import base64
import csv
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import requests
except ModuleNotFoundError:
    print("[SETUP] requests missing; installing it...", flush=True)
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "requests[socks]==2.32.3"
    ])
    import requests


# ===================== SETTINGS =====================

SOURCE_URL = (
    "https://github.com/williamnecoo1-pixel/testrw/"
    "raw/refs/heads/main/reality_configs.txt"
)

XRAY_BIN = os.environ.get("XRAY_BIN", "./xray/xray")
WORKERS = int(os.environ.get("WORKERS", "25"))
BASE_SOCKS_PORT = int(os.environ.get("BASE_SOCKS_PORT", "20000"))

XRAY_START_TIMEOUT = 8
CONNECT_TIMEOUT = 8
READ_TIMEOUT = 10

TESTS = [
    ("google", "https://www.google.com/generate_204", "204"),
    ("cloudflare", "https://cp.cloudflare.com/generate_204", "204"),
    ("apple", "http://captive.apple.com/hotspot-detect.html", "apple"),
]

print_lock = threading.Lock()


# ===================== LOGGING =====================

def log(message):
    with print_lock:
        print(message, flush=True)


def elapsed_text(seconds):
    seconds = max(0, int(seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)

    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def tail_file(path, max_lines=20):
    try:
        lines = Path(path).read_text(
            encoding="utf-8",
            errors="replace"
        ).splitlines()

        return "\n".join(lines[-max_lines:])
    except Exception:
        return ""


# ===================== DOWNLOAD SOURCE =====================

def fetch_source():
    log(f"[SOURCE] URL: {SOURCE_URL}")
    log("[SOURCE] Downloading config list...")

    response = requests.get(
        SOURCE_URL,
        headers={"User-Agent": "Mozilla/5.0 XHTTP-Checker/1.0"},
        timeout=(15, 60)
    )

    response.raise_for_status()

    if not response.text.strip():
        raise RuntimeError("The source file is empty.")

    lines = response.text.splitlines()

    log(f"[SOURCE] Download complete | raw lines: {len(lines)}")

    return lines


# ===================== SHARE LINK PARSING =====================

def b64decode_text(value):
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * ((4 - len(value) % 4) % 4)

    return base64.b64decode(value).decode(
        "utf-8",
        errors="strict"
    )


def first(query, key, default=""):
    values = query.get(key)
    return values[0] if values else default


def parse_link(link):
    """
    Convert a VLESS, VMess or Trojan share link
    into an Xray outbound configuration.
    """

    scheme = link.split("://", 1)[0].lower()

    # --------------------- VMESS ---------------------

    if scheme == "vmess":
        payload = link.split("://", 1)[1].split("#", 1)[0]
        obj = json.loads(b64decode_text(payload))

        address = str(obj.get("add", "")).strip()
        port = int(obj.get("port", 0))

        network = str(
            obj.get("net", obj.get("network", ""))
        ).lower()

        tls_value = str(
            obj.get("tls", obj.get("security", ""))
        ).lower()

        if (
            not address
            or port != 443
            or network != "xhttp"
            or tls_value not in ("tls", "true", "1")
        ):
            return None, "filtered"

        user_id = str(obj.get("id", "")).strip()

        if not user_id:
            return None, "missing_id"

        mode = str(obj.get("mode", "")).strip()
        old_type = str(obj.get("type", "")).strip()

        # Compatibility with collectors that stored XHTTP mode in "type".
        if not mode and old_type in (
            "auto",
            "packet-up",
            "stream-up",
            "stream-one"
        ):
            mode = old_type

        mode = mode or "packet-up"

        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": address,
                    "port": port,
                    "users": [{
                        "id": user_id,
                        "alterId": int(obj.get("aid", 0) or 0),
                        "security": str(
                            obj.get("scy", "auto") or "auto"
                        )
                    }]
                }]
            },
            "streamSettings": build_stream(
                sni=str(obj.get("sni") or address),
                host=str(obj.get("host") or address),
                path=str(obj.get("path") or "/"),
                mode=mode,
                fingerprint=str(obj.get("fp") or ""),
                alpn=str(obj.get("alpn") or "")
            )
        }

        return outbound, None

    # --------------------- VLESS / TROJAN ---------------------

    if scheme not in ("vless", "trojan"):
        return None, "unsupported_protocol"

    parsed = urllib.parse.urlsplit(link)
    query = urllib.parse.parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    address = parsed.hostname or ""
    port = parsed.port or 0

    network = first(
        query,
        "type",
        first(query, "network")
    ).lower()

    security = first(query, "security").lower()

    if port != 443 or network != "xhttp" or security != "tls":
        return None, "filtered"

    if not address:
        return None, "missing_address"

    sni = first(query, "sni", address)
    host = first(query, "host", address)
    path = first(query, "path", parsed.path or "/")
    mode = first(query, "mode", "packet-up")
    fingerprint = first(query, "fp")
    alpn = first(query, "alpn")

    stream = build_stream(
        sni=sni,
        host=host,
        path=path,
        mode=mode,
        fingerprint=fingerprint,
        alpn=alpn
    )

    # --------------------- VLESS ---------------------

    if scheme == "vless":
        user_id = urllib.parse.unquote(parsed.username or "")

        if not user_id:
            return None, "missing_id"

        settings = {
            "vnext": [{
                "address": address,
                "port": port,
                "users": [{
                    "id": user_id,
                    "encryption": first(query, "encryption", "none")
                }]
            }]
        }

        flow = first(query, "flow")

        if flow:
            settings["vnext"][0]["users"][0]["flow"] = flow

        return {
            "protocol": "vless",
            "settings": settings,
            "streamSettings": stream
        }, None

    # --------------------- TROJAN ---------------------

    password = urllib.parse.unquote(parsed.username or "")

    if not password:
        return None, "missing_password"

    return {
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": address,
                "port": port,
                "password": password
            }]
        },
        "streamSettings": stream
    }, None


# ===================== XHTTP STREAM SETTINGS =====================

def build_stream(sni, host, path, mode, fingerprint, alpn):
    tls = {
        "serverName": sni
    }

    if fingerprint:
        tls["fingerprint"] = fingerprint

    if alpn:
        tls["alpn"] = [
            item.strip()
            for item in alpn.split(",")
            if item.strip()
        ]

    xhttp = {
        "path": path or "/",
        "mode": mode or "packet-up"
    }

    if host:
        xhttp["host"] = host

    return {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": tls,
        "xhttpSettings": xhttp
    }


# ===================== XRAY CONFIG =====================

def make_config(outbound, socks_port):
    return {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": False
            }
        }],
        "outbounds": [
            dict(outbound, tag="proxy"),
            {
                "tag": "direct",
                "protocol": "freedom"
            },
            {
                "tag": "block",
                "protocol": "blackhole"
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{
                "type": "field",
                "inboundTag": ["socks-in"],
                "outboundTag": "proxy"
            }]
        }
    }


# ===================== XRAY STARTUP =====================

def port_ready(port, process, wait_seconds=XRAY_START_TIMEOUT):
    deadline = time.monotonic() + wait_seconds

    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False

        try:
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.25
            ):
                return True

        except OSError:
            time.sleep(0.1)

    return False


# ===================== ENDPOINT VALIDATION =====================

def endpoint_ok(name, response, expected):
    if expected == "204":
        return response.status_code == 204

    if expected == "apple":
        return (
            response.status_code == 200
            and "success" in response.text.lower()
        )

    return False


# ===================== TEST ONE CONFIG =====================

def test_one(index, link, total):
    label = f"[{index + 1}/{total}]"

    result = {
        "index": index,
        "link": link,
        "status": "FAILED",
        "reason": "",
        "delay_ms": "",
        "google": "",
        "cloudflare": "",
        "apple": ""
    }

    log(f"{label} START | parsing config")

    try:
        outbound, reason = parse_link(link)

        if reason:
            result["status"] = "SKIPPED"
            result["reason"] = reason

            log(f"{label} SKIPPED | {reason}")

            return result

        protocol = outbound.get("protocol", "unknown")

        log(f"{label} PARSED | protocol={protocol}")
        log(f"{label} XRAY | preparing process")

        socks_port = BASE_SOCKS_PORT + index

        with tempfile.TemporaryDirectory(
            prefix="xray-check-"
        ) as temp_dir:

            config_path = Path(temp_dir) / "config.json"
            xray_log_path = Path(temp_dir) / "xray.log"

            config_path.write_text(
                json.dumps(
                    make_config(outbound, socks_port),
                    ensure_ascii=False
                ),
                encoding="utf-8"
            )

            with open(
                xray_log_path,
                "w",
                encoding="utf-8"
            ) as xray_log:

                process = subprocess.Popen(
                    [
                        XRAY_BIN,
                        "run",
                        "-c",
                        str(config_path)
                    ],
                    stdout=xray_log,
                    stderr=subprocess.STDOUT
                )

                try:
                    log(
                        f"{label} XRAY | waiting for SOCKS "
                        f"127.0.0.1:{socks_port}"
                    )

                    if not port_ready(socks_port, process):
                        details = tail_file(xray_log_path)

                        result["status"] = "FAILED"
                        result["reason"] = "xray_start_or_proxy_failed"

                        log(f"{label} XRAY FAILED")

                        if details:
                            log(f"{label} XRAY LOG:\n{details}")

                        return result

                    log(
                        f"{label} XRAY READY | "
                        f"SOCKS 127.0.0.1:{socks_port}"
                    )

                    proxy = f"socks5h://127.0.0.1:{socks_port}"

                    session = requests.Session()
                    session.trust_env = False
                    session.proxies = {
                        "http": proxy,
                        "https": proxy
                    }

                    timings = {}
                    checks = {}

                    # Test each endpoint and print its result immediately.
                    for name, url, expected in TESTS:
                        log(f"{label} {name.upper()} | connecting")

                        started = time.perf_counter()

                        try:
                            response = session.get(
                                url,
                                timeout=(
                                    CONNECT_TIMEOUT,
                                    READ_TIMEOUT
                                ),
                                allow_redirects=False,
                                headers={
                                    "User-Agent":
                                    "Mozilla/5.0 XHTTP-Checker/1.0"
                                }
                            )

                            elapsed = round(
                                (time.perf_counter() - started) * 1000,
                                1
                            )

                            ok = endpoint_ok(
                                name,
                                response,
                                expected
                            )

                            if ok:
                                checks[name] = "OK"
                                timings[name] = elapsed

                                log(
                                    f"{label} {name.upper()} | PASS | "
                                    f"{elapsed} ms | "
                                    f"HTTP {response.status_code}"
                                )

                            else:
                                checks[name] = (
                                    f"HTTP_{response.status_code}"
                                )

                                log(
                                    f"{label} {name.upper()} | FAIL | "
                                    f"{elapsed} ms | "
                                    f"HTTP {response.status_code}"
                                )

                        except requests.RequestException as exc:
                            elapsed = round(
                                (time.perf_counter() - started) * 1000,
                                1
                            )

                            checks[name] = type(exc).__name__

                            log(
                                f"{label} {name.upper()} | FAIL | "
                                f"{elapsed} ms | "
                                f"{type(exc).__name__}: {exc}"
                            )

                    for name in ("google", "cloudflare", "apple"):
                        result[name] = checks.get(name, "NOT_TESTED")

                    # --------------------- FINAL RESULT ---------------------

                    if timings:
                        sorted_times = sorted(timings.values())
                        middle = len(sorted_times) // 2

                        if len(sorted_times) % 2:
                            delay = sorted_times[middle]
                        else:
                            delay = round(
                                (
                                    sorted_times[middle - 1]
                                    + sorted_times[middle]
                                ) / 2,
                                1
                            )

                        result["status"] = "WORKING"
                        result["reason"] = (
                            f"{len(timings)}/3 endpoints passed"
                        )
                        result["delay_ms"] = delay

                        log(
                            f"{label} RESULT | WORKING | "
                            f"delay={delay} ms | "
                            f"passed {len(timings)}/3"
                        )

                    else:
                        result["status"] = "FAILED"
                        result["reason"] = "no_test_endpoint_passed"

                        log(
                            f"{label} RESULT | FAILED | "
                            f"0/3 endpoints passed"
                        )

                    return result

                finally:
                    log(f"{label} XRAY | stopping process")

                    process.terminate()

                    try:
                        process.wait(timeout=2)

                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)

    except Exception as exc:
        result["status"] = "FAILED"
        result["reason"] = (
            f"parse_or_runtime_error:{type(exc).__name__}"
        )

        log(
            f"{label} ERROR | "
            f"{type(exc).__name__}: {exc}"
        )

        return result


# ===================== MAIN =====================

def main():
    global_start = time.monotonic()

    log("=" * 70)
    log("[START] XHTTP Real Delay Checker")
    log(f"[INFO] Python: {sys.version.split()[0]}")
    log(f"[INFO] Xray binary: {XRAY_BIN}")
    log(f"[INFO] Workers: {WORKERS}")
    log("=" * 70)

    if not Path(XRAY_BIN).exists():
        raise SystemExit(
            f"[FATAL] Xray binary not found: {XRAY_BIN}"
        )

    # --------------------- Download ---------------------

    try:
        raw_lines = fetch_source()

    except Exception as exc:
        raise SystemExit(
            f"[FATAL] Could not download source configs: {exc}"
        )

    # --------------------- Deduplicate ---------------------

    seen = set()
    links = []

    for line in raw_lines:
        line = line.strip()

        if (
            not line
            or line.startswith("#")
            or "://" not in line
        ):
            continue

        if line not in seen:
            seen.add(line)
            links.append(line)

    total = len(links)

    log(f"[SOURCE] Unique links: {total}")

    if total == 0:
        raise SystemExit("[FATAL] No configs found in source.")

    log("[INFO] Testing endpoints:")
    log("[INFO] Google: https://www.google.com/generate_204")
    log("[INFO] Cloudflare: https://cp.cloudflare.com/generate_204")
    log("[INFO] Apple: http://captive.apple.com/hotspot-detect.html")
    log("[INFO] Delay = HTTP response time through the proxy")
    log("=" * 70)

    # --------------------- Concurrent tests ---------------------

    results = []

    completed = 0
    working_count = 0
    failed_count = 0
    skipped_count = 0

    with ThreadPoolExecutor(
        max_workers=WORKERS
    ) as pool:

        futures = {
            pool.submit(test_one, index, link, total): index
            for index, link in enumerate(links)
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)

            completed += 1

            if result["status"] == "WORKING":
                working_count += 1

            elif result["status"] == "FAILED":
                failed_count += 1

            elif result["status"] == "SKIPPED":
                skipped_count += 1

            elapsed = time.monotonic() - global_start

            rate = (
                completed / elapsed
                if elapsed > 0
                else 0
            )

            remaining = (
                (total - completed) / rate
                if rate > 0
                else 0
            )

            percentage = completed * 100 / total

            log("-" * 70)

            log(
                f"[PROGRESS] {completed}/{total} "
                f"({percentage:.2f}%) | "
                f"Working: {working_count} | "
                f"Failed: {failed_count} | "
                f"Skipped: {skipped_count}"
            )

            log(
                f"[TIME] Elapsed: {elapsed_text(elapsed)} | "
                f"ETA: {elapsed_text(remaining)}"
            )

            log("-" * 70)

    # --------------------- Sort results ---------------------

    results.sort(
        key=lambda item: item["index"]
    )

    working = [
        result
        for result in results
        if result["status"] == "WORKING"
    ]

    failed = [
        result
        for result in results
        if result["status"] == "FAILED"
    ]

    skipped = [
        result
        for result in results
        if result["status"] == "SKIPPED"
    ]

    # --------------------- Save working configs ---------------------

    working_sorted = sorted(
        working,
        key=lambda item: float(item["delay_ms"])
    )

    Path("working_configs.txt").write_text(
        "\n".join(
            item["link"]
            for item in working_sorted
        ) + ("\n" if working_sorted else ""),
        encoding="utf-8"
    )

    # --------------------- Save failed configs ---------------------

    Path("failed_configs.txt").write_text(
        "\n".join(
            item["link"]
            for item in failed
        ) + ("\n" if failed else ""),
        encoding="utf-8"
    )

    # --------------------- Save CSV ---------------------

    with open(
        "results.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        fields = [
            "index",
            "status",
            "reason",
            "delay_ms",
            "google",
            "cloudflare",
            "apple",
            "link"
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()

        for result in results:
            writer.writerow({
                key: result.get(key, "")
                for key in fields
            })

    # --------------------- Summary ---------------------

    elapsed = time.monotonic() - global_start

    log("=" * 70)
    log("[DONE] XHTTP Checker finished")
    log(f"[SUMMARY] Total: {total}")
    log(f"[SUMMARY] Working: {len(working)}")
    log(f"[SUMMARY] Failed: {len(failed)}")
    log(f"[SUMMARY] Skipped: {len(skipped)}")
    log(f"[SUMMARY] Duration: {elapsed_text(elapsed)}")
    log("[OUTPUT] working_configs.txt")
    log("[OUTPUT] failed_configs.txt")
    log("[OUTPUT] results.csv")
    log("=" * 70)


if __name__ == "__main__":
    main()
