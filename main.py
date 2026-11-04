import os
import sys
import time
import random
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from python_v2ray.downloader import BinaryDownloader
from python_v2ray.config_parser import parse_uri
from python_v2ray.tester import ConnectionTester

# ============================================================
# إعدادات قابلة للتعديل عبر متغيرات البيئة
# ============================================================

CONFIGS_URL = "https://github.com/williamnecoo1-pixel/testrw/raw/refs/heads/main/reality_configs.txt"

TEST_URLS = [
    "https://www.google.com/generate_204",                        # 0
    "http://cp.cloudflare.com/generate_204",                     # 1  ← نبدأ بها (أسرع)
    "http://captive.apple.com/hotspot-detect.html",              # 2
    "http://edge-http.microsoft.com/captiveportal/generate_204", # 3
]

MAX_WORKERS      = int(os.getenv("MAX_WORKERS", "40"))          # توازي
PER_TEST_TIMEOUT = int(os.getenv("PER_TEST_TIMEOUT", "8"))      # ثانية لكل URL
LIMIT_PER_RUN    = int(os.getenv("LIMIT_PER_RUN", "0"))         # 0 = بلا حد
SHUFFLE          = os.getenv("SHUFFLE", "0") == "1"             # خلط عشوائي
PROGRESS_EVERY   = int(os.getenv("PROGRESS_EVERY", "50"))       # طباعة كل X

OUTPUT_FILE = Path("working.txt")

# ============================================================
# Logger
# ============================================================

_log_lock = threading.Lock()

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
# جلب الإعدادات
# ============================================================

def fetch_configs(url: str) -> List[str]:
    log(f"جلب الإعدادات من: {url}", "⬇️")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vless-tester/2.0"})
        with urllib.request.urlopen(req, timeout=60) as r:
            content = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        log(f"فشل الجلب: {e}", "❌")
        return []

    seen = set()
    configs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
            continue
        if line in seen:
            continue
        seen.add(line)
        configs.append(line)

    log(f"تم العثور على {len(configs)} إعداد (بعد إزالة التكرارات)", "✅")
    return configs

# ============================================================
# اختبار إعداد واحد — Fast-fail على Cloudflare
# ============================================================

def _probe(tester: ConnectionTester, parsed, url: str) -> Tuple[bool, int]:
    """اختبار واحد. يرجع (نجح؟، ms)."""
    try:
        t0 = time.time()
        results = tester.test_uris([parsed], test_url=url)
        elapsed = int((time.time() - t0) * 1000)
        ok = any(
            r.get("status") == "success" and r.get("ping_ms", -1) >= 0
            for r in results
        )
        return ok, elapsed
    except Exception:
        return False, -1


def test_one_config(cfg: str, tester: ConnectionTester) -> Tuple[str, bool, str]:
    """يرجع (config، نجح؟، وصف)."""
    parsed = parse_uri(cfg)
    if not parsed:
        return cfg, False, "parse فشل"

    # المرحلة 1: Fast-fail على Cloudflare (أسرع)
    ok, ms = _probe(tester, parsed, TEST_URLS[1])
    if not ok:
        return cfg, False, f"cloudflare ✗ ({ms}ms)"

    # المرحلة 2: تحقق من Google + Apple (+ Microsoft اختياري)
    for i in (0, 2, 3):
        ok, ms2 = _probe(tester, parsed, TEST_URLS[i])
        if ok:
            return cfg, True, f"cloudflare ✅ + {TEST_URLS[i].split('/')[2]} ✅ ({ms}ms)"

    return cfg, False, f"cloudflare ✅ لكن الباقي ✗"

# ============================================================
# main
# ============================================================

def main() -> None:
    log_header("VLESS Concurrent Tester — بدأ")
    log(f"Workers={MAX_WORKERS} | Timeout/URL={PER_TEST_TIMEOUT}s | Limit={LIMIT_PER_RUN or '∞'} | Shuffle={SHUFFLE}", "⚙️")

    # --- تجهيز Xray ---
    log_header("1) تجهيز Xray-core")
    root = Path(".")
    try:
        BinaryDownloader(root).ensure_all()
        log("Xray-core جاهز", "✅")
    except Exception as e:
        log(f"فشل تجهيز Xray: {e}", "❌")
        sys.exit(1)

    # --- جلب الإعدادات ---
    log_header("2) جلب الإعدادات")
    configs = fetch_configs(CONFIGS_URL)
    if not configs:
        OUTPUT_FILE.write_text("", encoding="utf-8")
        log("لا توجد إعدادات — إنهاء", "⚠️")
        sys.exit(0)

    # --- عشوائية + حد ---
    if SHUFFLE:
        random.shuffle(configs)
    if LIMIT_PER_RUN > 0:
        configs = configs[:LIMIT_PER_RUN]

    total = len(configs)
    log(f"سيتم اختبار {total} إعداد بـ {MAX_WORKERS} worker", "🎯")

    # --- تجهيز المُختبر ---
    log_header("3) تجهيز المُختبر")
    tester = ConnectionTester(
        vendor_path=str(root / "vendor"),
        core_engine_path=str(root / "core_engine"),
    )
    log("المُختبر جاهز", "✅")

    # --- تفريغ working.txt قبل البدء ---
    OUTPUT_FILE.write_text("", encoding="utf-8")
    log(f"تم تفريغ {OUTPUT_FILE} — سيتم الكتابة تدريجياً", "📝")

    # --- الاختبار المتوازي ---
    log_header(f"4) اختبار متوازي ({total} إعداد)")

    stats = {"done": 0, "working": 0, "failed": 0, "error": 0}
    stats_lock = threading.Lock()
    out_lock = threading.Lock()
    start = time.time()

    def worker(cfg: str) -> Tuple[str, bool, str]:
        try:
            return test_one_config(cfg, tester)
        except Exception as e:
            return cfg, False, f"exception: {type(e).__name__}: {e}"

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(worker, c): c for c in configs}

        for fut in as_completed(futures):
            try:
                cfg, ok, info = fut.result(timeout=PER_TEST_TIMEOUT * 4 + 30)
            except Exception as e:
                cfg = futures[fut]
                ok, info = False, f"watchdog: {e}"

            with stats_lock:
                stats["done"] += 1
                if ok:
                    stats["working"] += 1
                else:
                    stats["failed"] += 1
                done, working = stats["done"], stats["working"]

            # كتابة فورية للناجح
            if ok:
                tag = cfg.split("#")[-1] if "#" in cfg else cfg[:50]
                with out_lock:
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                        f.write(cfg + "\n")
                log(f"✅ [{done}/{total}] يعمل: {tag} — {info}", "★")

            # progress كل X
            if done % PROGRESS_EVERY == 0 or done == total:
                elapsed = int(time.time() - start)
                rate = done / elapsed if elapsed > 0 else 0
                eta = int((total - done) / rate) if rate > 0 else 0
                log(f"📊 [{done}/{total}] ✅{working} ✗{stats['failed']} | {rate:.1f} cfg/s | ETA {eta}s", "⏱️")

    # --- ملخص نهائي ---
    log_header("5) ملخص")
    elapsed = int(time.time() - start)
    log(f"الوقت الكلي: {elapsed}s ({elapsed//60}m{elapsed%60}s)", "⏱️")
    log(f"تم اختبار: {total} | يعمل: {stats['working']} | فشل: {stats['failed']}", "📊")

    if stats["working"] == 0:
        log("لم يعمل أي إعداد — working.txt فارغ", "⚠️")
    else:
        log(f"تم حفظ {stats['working']} إعداد فـ {OUTPUT_FILE}", "🎉")

    log_header("انتهى")


if __name__ == "__main__":
    main()
