import os
import sys
import time
import random
import socket
import subprocess
import tempfile
import threading
import urllib.request
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple
from urllib.parse import urlparse, parse_qs
import requests

from python_v2ray.downloader import BinaryDownloader

# ============================================================
# الإعدادات
# ============================================================
CONFIGS_URL = "https://github.com/williamnecoo1-pixel/testrw/raw/refs/heads/main/reality_configs.txt"

# ✅ المواقع ديال التيست
TEST_URLS = [
    "https://www.google.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
    "http://captive.apple.com/hotspot-detect.html",
    "http://www.gstatic.com/generate_204",
]

MAX_WORKERS      = int(os.getenv("MAX_WORKERS", "40"))          
PER_TEST_TIMEOUT = int(os.getenv("PER_TEST_TIMEOUT", "8"))      
LIMIT_PER_RUN    = int(os.getenv("LIMIT_PER_RUN", "0"))         
SHUFFLE          = os.getenv("SHUFFLE", "0") == "1"
PROGRESS_EVERY   = int(os.getenv("PROGRESS_EVERY", "50"))

OUTPUT_FILE = Path("working.txt")
_log_lock = threading.Lock()

# ============================================================
# Logger
# ============================================================
def log(msg: str, tag: str = "•") -> None:
    with _log_lock:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"[{ts}] {tag} {msg}", flush=True)

def log_header(title: str) -> None:
    with _log_lock:
        print("\n" + "=" * 60, flush=True)
        print(f"  {title}", flush=True)
        print("=" * 60, flush=True)

# ============================================================
# تحويل رابط VLESS إلى إعدادات Xray JSON
# ============================================================
def vless_to_xray(uri, local_port):
    parsed = urlparse(uri)
    uuid = parsed.username
    host = parsed.hostname
    port = parsed.port
    params = parse_qs(parsed.query)
    
    network = params.get('type', ['tcp'])[0]
    security = params.get('security', ['none'])[0]
    sni = params.get('sni', [''])[0]
    alpn = params.get('alpn', [''])[0].split(',') if 'alpn' in params else []
    ech = params.get('ech', [''])[0]
    host_header = params.get('host', [''])[0]
    path = params.get('path', [''])[0]
    mode = params.get('mode', [''])[0]
    
    # ✅ استخراج البصمة (Fingerprint) من الرابط
    fp = params.get('fp', [''])[0]
    
    stream = {"network": network, "security": security}
    
    if security == "tls":
        tls = {}
        if sni: tls["serverName"] = sni
        if alpn: tls["alpn"] = alpn
        if fp: tls["fingerprint"] = fp  # 👈 الحل الأساسي: تمرير البصمة
        if ech: tls["ech"] = {"query": ech.replace("%2B", "+")}
        stream["tlsSettings"] = tls
        
    if network == "xhttp":
        stream["xhttpSettings"] = {"host": host_header, "path": path, "mode": mode}
    elif network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_header} if host_header else {}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": path}

    return {
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host, "port": port,
                    "users": [{"id": uuid, "encryption": "none"}]
                }]
            },
            "streamSettings": stream
        }]
    }

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

# ✅ دالة كتسنى حتى يفتح البورت ديال Xray
def wait_for_port(port, timeout=3):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except:
            time.sleep(0.1)
    return False

def check_url(url, proxy_port, timeout):
    proxies = {
        'http': f'socks5h://127.0.0.1:{proxy_port}',
        'https': f'socks5h://127.0.0.1:{proxy_port}'
    }
    try:
        r = requests.get(url, proxies=proxies, timeout=(3, timeout), headers={'User-Agent': 'Mozilla/5.0'})
        return r.status_code in [200, 204]
    except:
        return False

# ============================================================
# اختبار كونفيغ واحد
# ============================================================
def test_one_config(cfg: str, xray_bin: str) -> Tuple[str, bool, str]:
    temp_path = ""
    log_path = ""
    proc = None
    try:
        port = get_free_port()
        config = vless_to_xray(cfg, port)
        
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            temp_path = f.name
            
        # ✅ ملف اللوجات ديال Xray
        log_file = tempfile.NamedTemporaryFile('w+', suffix='.log', delete=False)
        log_path = log_file.name
            
        proc = subprocess.Popen(
            [xray_bin, "run", "-c", temp_path],
            stdout=log_file,
            stderr=log_file
        )
        
        # ✅ نسناو البورت يفتح
        if not wait_for_port(port, timeout=3):
            err = "Xray failed to bind"
            try:
                log_file.seek(0)
                err = log_file.read().strip().split('\n')[-1][:80]
            except: pass
            return cfg, False, err
            
        success = False
        info = ""
        
        # ✅ رجعنا الاختبار المتوازي (Concurrent) باش يكون سريع
        with ThreadPoolExecutor(max_workers=len(TEST_URLS)) as ex:
            futures = {ex.submit(check_url, url, port, PER_TEST_TIMEOUT): url for url in TEST_URLS}
            for fut in as_completed(futures):
                try:
                    if fut.result():
                        success = True
                        info = f"نجح عبر {futures[fut].split('/')[2]}"
                        break # إلا نجح شي واحد، كنقطعو الباقي
                except:
                    pass
                
        # إغلاق Xray
        proc.terminate()
        proc.wait(timeout=2)
        
        # إلا فشل، كنقرو آخر خطأ من Xray
        if not success:
            try:
                log_file.seek(0)
                err_log = log_file.read().strip()
                info = err_log.split('\n')[-1][:80] if err_log else "Connection failed/Timeout"
            except: pass
                
        return cfg, success, info
    except Exception as e:
        return cfg, False, f"Error: {e}"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()
        if temp_path and os.path.exists(temp_path): os.remove(temp_path)
        if log_path and os.path.exists(log_path): os.remove(log_path)

def fetch_configs(url: str) -> List[str]:
    log(f"جلب الإعدادات من: {url}", "⬇️")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vless-tester/3.0"})
        with urllib.request.urlopen(req, timeout=60) as r:
            content = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        log(f"فشل الجلب: {e}", "❌")
        return []

    seen = set()
    configs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
            continue
        if line in seen:
            continue
        seen.add(line)
        configs.append(line)

    log(f"تم العثور على {len(configs)} إعداد (بعد إزالة التكرارات)", "✅")
    return configs

# ============================================================
# Main
# ============================================================
def main() -> None:
    log_header("VLESS Concurrent Tester (Single Tunnel) — بدأ")
    log(f"Workers={MAX_WORKERS} | Timeout/URL={PER_TEST_TIMEOUT}s | Limit={LIMIT_PER_RUN or '∞'}", "⚙️")

    # تجهيز Xray
    log_header("1) تجهيز Xray-core")
    root = Path(".")
    try:
        BinaryDownloader(root).ensure_all()
        xray_bin = None
        for p in root.rglob("xray*"):
            if p.is_file() and os.access(p, os.X_OK):
                xray_bin = str(p)
                break
        
        if not xray_bin:
            raise Exception("Xray binary not found")
            
        log(f"Xray-core جاهز: {xray_bin}", "✅")
    except Exception as e:
        log(f"فشل تجهيز Xray: {e}", "❌")
        sys.exit(1)

    # جلب الإعدادات
    log_header("2) جلب الإعدادات")
    configs = fetch_configs(CONFIGS_URL)
    if not configs:
        OUTPUT_FILE.write_text("", encoding="utf-8")
        sys.exit(0)

    if SHUFFLE: random.shuffle(configs)
    if LIMIT_PER_RUN > 0: configs = configs[:LIMIT_PER_RUN]

    total = len(configs)
    OUTPUT_FILE.write_text("", encoding="utf-8")

    # الاختبار المتوازي
    log_header(f"3) اختبار متوازي ({total} إعداد)")
    stats = {"done": 0, "working": 0, "failed": 0}
    stats_lock = threading.Lock()
    out_lock = threading.Lock()
    start = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_one_config, c, xray_bin): c for c in configs}

        for fut in as_completed(futures):
            try:
                cfg, ok, info = fut.result()
            except Exception as e:
                cfg, ok, info = futures[fut], False, f"watchdog: {e}"

            with stats_lock:
                stats["done"] += 1
                if ok: stats["working"] += 1
                else: stats["failed"] += 1
                done, working = stats["done"], stats["working"]

            if ok:
                tag = cfg.split("#")[-1] if "#" in cfg else cfg[:50]
                with out_lock:
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                        f.write(cfg + "\n")
                log(f"✅ [{done}/{total}] يعمل: {tag} — {info}", "★")

            if done % PROGRESS_EVERY == 0 or done == total:
                elapsed = int(time.time() - start)
                rate = done / elapsed if elapsed > 0 else 0
                eta = int((total - done) / rate) if rate > 0 else 0
                log(f"📊 [{done}/{total}] ✅{working} ✗{stats['failed']} | {rate:.1f} cfg/s | ETA {eta}s", "⏱️")

    # النتيجة
    log_header("4) ملخص")
    elapsed = int(time.time() - start)
    log(f"الوقت الكلي: {elapsed}s ({elapsed//60}m{elapsed%60}s)", "⏱️")
    log(f"تم اختبار: {total} | يعمل: {stats['working']} | فشل: {stats['failed']}", "📊")

if __name__ == "__main__":
    main()
