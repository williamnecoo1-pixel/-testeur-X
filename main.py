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
    # Allow `python main.py` to work even if the runner skipped requirements.txt.
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "requests[socks]==2.32.3"
    ])
    import requests

SOURCE_URL = "https://github.com/williamnecoo1-pixel/testrw/raw/refs/heads/main/reality_configs.txt"
XRAY_BIN = os.environ.get("XRAY_BIN", "./xray/xray")
WORKERS = int(os.environ.get("WORKERS", "25"))
BASE_SOCKS_PORT = int(os.environ.get("BASE_SOCKS_PORT", "20000"))

# A config passes when at least one independent endpoint returns its expected response.
TESTS = [
    ("google", "https://www.google.com/generate_204", "204"),
    ("cloudflare", "https://cp.cloudflare.com/generate_204", "204"),
    ("apple", "http://captive.apple.com/hotspot-detect.html", "apple"),
]

print_lock = threading.Lock()


def log(message):
    with print_lock:
        print(message, flush=True)


def fetch_source():
    """Download the input list from the configured raw GitHub URL."""
    response = requests.get(
        SOURCE_URL,
        headers={"User-Agent": "Mozilla/5.0 XHTTP-Checker/1.0"},
        timeout=(15, 60)
    )
    response.raise_for_status()
    if not response.text.strip():
        raise RuntimeError("The source file is empty.")
    return response.text.splitlines()


def b64decode_text(value):
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.b64decode(value).decode("utf-8", errors="strict")


def first(query, key, default=""):
    values = query.get(key)
    return values[0] if values else default


def parse_link(link):
    """Convert a VLESS/VMess/Trojan share link into an Xray outbound."""
    scheme = link.split("://", 1)[0].lower()

    if scheme == "vmess":
        payload = link.split("://", 1)[1].split("#", 1)[0]
        obj = json.loads(b64decode_text(payload))
        address = str(obj.get("add", "")).strip()
        port = int(obj.get("port", 0))
        network = str(obj.get("net", obj.get("network", ""))).lower()
        tls_value = str(obj.get("tls", obj.get("security", ""))).lower()
        if not address or port != 443 or network != "xhttp" or tls_value not in ("tls", "true", "1"):
            return None, "filtered"
        user_id = str(obj.get("id", "")).strip()
        if not user_id:
            return None, "missing_id"

        # Some earlier collectors incorrectly stored packet-up in `type`.
        # Treat it as XHTTP mode only when it is a recognized mode value.
        mode = str(obj.get("mode", "")).strip()
        old_type = str(obj.get("type", "")).strip()
        if not mode and old_type in ("auto", "packet-up", "stream-up", "stream-one"):
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
                        "security": str(obj.get("scy", "auto") or "auto")
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

    if scheme not in ("vless", "trojan"):
        return None, "unsupported_protocol"

    parsed = urllib.parse.urlsplit(link)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    address = parsed.hostname or ""
    port = parsed.port or 0
    network = first(query, "type", first(query, "network")).lower()
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

    stream = build_stream(sni, host, path, mode, fingerprint, alpn)

    if scheme == "vless":
        user_id = urllib.parse.unquote(parsed.username or "")
        if not user_id:
            return None, "missing_id"
        settings = {"vnext": [{
            "address": address,
            "port": port,
            "users": [{"id": user_id, "encryption": first(query, "encryption", "none")}]
        }]}
        flow = first(query, "flow")
        if flow:
            settings["vnext"][0]["users"][0]["flow"] = flow
        return {"protocol": "vless", "settings": settings, "streamSettings": stream}, None

    password = urllib.parse.unquote(parsed.username or "")
    if not password:
        return None, "missing_password"
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": address, "port": port, "password": password}]},
        "streamSettings": stream
    }, None


def build_stream(sni, host, path, mode, fingerprint, alpn):
    tls = {"serverName": sni}
    if fingerprint:
        tls["fingerprint"] = fingerprint
    if alpn:
        tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]

    xhttp = {"path": path or "/", "mode": mode or "packet-up"}
    if host:
        xhttp["host"] = host

    return {
        "method": "xhttp",
        "xhttpSettings": xhttp,
        "security": "tls",
        "tlsSettings": tls
    }


def make_config(outbound, socks_port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        }],
        "outbounds": [
            dict(outbound, tag="proxy"),
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"}]
        }
    }


def port_ready(port, process, wait_seconds=8):
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def endpoint_ok(name, response, expected):
    if expected == "204":
        return response.status_code == 204
    if expected == "apple":
        return response.status_code == 200 and "success" in response.text.lower()
    return False


def test_one(index, link):
    try:
        outbound, reason = parse_link(link)
        if reason:
            return {"index": index, "link": link, "status": "SKIPPED", "reason": reason,
                    "delay_ms": "", "google": "", "cloudflare": "", "apple": ""}

        socks_port = BASE_SOCKS_PORT + index
        with tempfile.TemporaryDirectory(prefix="xray-check-") as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(
                json.dumps(make_config(outbound, socks_port), ensure_ascii=False),
                encoding="utf-8"
            )

            process = subprocess.Popen(
                [XRAY_BIN, "run", "-c", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            try:
                if not port_ready(socks_port, process):
                    return {"index": index, "link": link, "status": "FAILED",
                            "reason": "xray_start_or_proxy_failed", "delay_ms": "",
                            "google": "", "cloudflare": "", "apple": ""}

                proxy = f"socks5h://127.0.0.1:{socks_port}"
                session = requests.Session()
                session.trust_env = False
                session.proxies = {"http": proxy, "https": proxy}
                timings = {}
                checks = {}

                for name, url, expected in TESTS:
                    started = time.perf_counter()
                    try:
                        response = session.get(
                            url,
                            timeout=(8, 10),
                            allow_redirects=False,
                            headers={"User-Agent": "Mozilla/5.0 XHTTP-Checker/1.0"}
                        )
                        elapsed = round((time.perf_counter() - started) * 1000, 1)
                        ok = endpoint_ok(name, response, expected)
                        checks[name] = "OK" if ok else f"HTTP_{response.status_code}"
                        if ok:
                            timings[name] = elapsed
                    except requests.RequestException as exc:
                        checks[name] = type(exc).__name__

                if timings:
                    # Median across successful endpoints; robust against one unusually fast result.
                    sorted_times = sorted(timings.values())
                    delay = sorted_times[len(sorted_times) // 2]
                    return {
                        "index": index, "link": link, "status": "WORKING",
                        "reason": f"{len(timings)}/3 endpoints passed",
                        "delay_ms": delay,
                        "google": checks.get("google", ""),
                        "cloudflare": checks.get("cloudflare", ""),
                        "apple": checks.get("apple", "")
                    }

                return {
                    "index": index, "link": link, "status": "FAILED",
                    "reason": "no_test_endpoint_passed",
                    "delay_ms": "",
                    "google": checks.get("google", ""),
                    "cloudflare": checks.get("cloudflare", ""),
                    "apple": checks.get("apple", "")
                }
            finally:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)

    except Exception as exc:
        return {"index": index, "link": link, "status": "FAILED",
                "reason": f"parse_or_runtime_error:{type(exc).__name__}",
                "delay_ms": "", "google": "", "cloudflare": "", "apple": ""}


def main():
    if not Path(XRAY_BIN).exists():
        raise SystemExit(f"Xray binary not found: {XRAY_BIN}")
    log(f"[SOURCE] Downloading configs from: {SOURCE_URL}")
    try:
        raw_lines = fetch_source()
    except Exception as exc:
        raise SystemExit(f"Could not download source configs: {exc}")
    seen = set()
    links = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#") or "://" not in line:
            continue
        if line not in seen:
            seen.add(line)
            links.append(line)

    log(f"[START] Unique downloaded links: {len(links)} | workers: {WORKERS}")

    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(test_one, i, link): (i, link) for i, link in enumerate(links)}
        for done, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            log(f"[{done}/{len(links)}] {result['status']} | {result['reason']}")

    results.sort(key=lambda x: x["index"])
    working = [r for r in results if r["status"] == "WORKING"]
    failed = [r for r in results if r["status"] == "FAILED"]

    Path("working_configs.txt").write_text(
        "\n".join(r["link"] for r in sorted(working, key=lambda x: float(x["delay_ms"]))) +
        ("\n" if working else ""),
        encoding="utf-8"
    )
    Path("failed_configs.txt").write_text(
        "\n".join(r["link"] for r in failed) + ("\n" if failed else ""),
        encoding="utf-8"
    )

    with open("results.csv", "w", newline="", encoding="utf-8") as f:
        fields = ["index", "status", "reason", "delay_ms", "google", "cloudflare", "apple", "link"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for result in results:
            writer.writerow({key: result.get(key, "") for key in fields})

    log(f"[DONE] Working: {len(working)} | Failed: {len(failed)} | Skipped: {sum(r['status']=='SKIPPED' for r in results)}")


if __name__ == "__main__":
    main()
