import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from python_v2ray.downloader import BinaryDownloader
from python_v2ray.config_parser import parse_uri
from python_v2ray.tester import ConnectionTester

# ============================================================
# إعدادات
# ============================================================

CONFIGS_URL = "https://github.com/williamnecoo1-pixel/testrw/raw/refs/heads/main/reality_configs.txt"

TEST_URLS = [
    "https://www.google.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
    "http://captive.apple.com/hotspot-detect.html",
    "http://edge-http.microsoft.com/captiveportal/generate_204",
]

OUTPUT_FILE = Path("working.txt")

# كل اختبار على حدة عندو timeout (ثانية) — باش ما يتعلقش الـ job
PER_TEST_TIMEOUT = 20

# ============================================================
# Logger بسيط: timestamp + flush فوري
# ============================================================

def log(msg: str, tag: str = "•") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {tag} {msg}", flush=True)

def log_header(title: str) -> None:
    print("\n" + "=" * 60, flush=True)
    print(f"  {title}", flush=True)
    print("=" * 60, flush=True)

# ============================================================
# 1) جلب الإعدادات
# ============================================================

def fetch_configs(url: str) -> List[str]:
    log(f"جلب الإعدادات من: {url}", "⬇️")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vless-tester/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            content = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        log(f"فشل الجلب: {e}", "❌")
        return []

    configs = [
        line.strip()
        for line in content.splitlines()
        if line.strip().startswith(("vless://", "vmess://", "trojan://", "ss://"))
    ]
    log(f"تم العثور على {len(configs)} إعداد", "✅")
    return configs

# ============================================================
# 2) اختبار إعداد واحد
# ============================================================

def test_config(config_uri: str, tester: ConnectionTester) -> bool:
    parsed = parse_uri(config_uri)
    if not parsed:
        log("فشل تحليل الرابط (parse_uri رجع None)", "⚠️")
        return False

    for url in TEST_URLS:
        try:
            t0 = time.time()
            log(f"    → اختبار مقابل {url} (timeout={PER_TEST_TIMEOUT}s)", "🧪")

            results = tester.test_uris([parsed], test_url=url)
            elapsed = int((time.time() - t0) * 1000)

            ok = any(
                r.get("status") == "success" and r.get("ping_ms", -1) >= 0
                for r in results
            )
            if ok:
                log(f"    ✅ نجح مع {url} (زمن الاستجابة: {elapsed}ms)", "★")
                return True
            log(f"    ✗ فشل مع {url} ({elapsed}ms)", " ")

        except Exception as e:
            log(f"    ❌ خطأ مع {url}: {type(e).__name__}: {e}", " ")

    return False

# ============================================================
# 3) main
# ============================================================

def main() -> None:
    log_header("VLESS Config Tester — بدأ التشغيل")

    # --- أ. تجهيز Xray-core ---
    log_header("المرحلة 1: تجهيز Xray-core")
    project_root = Path(".")
    downloader = BinaryDownloader(project_root)
    try:
        downloader.ensure_all()
        log("Xray-core جاهز", "✅")
    except Exception as e:
        log(f"فشل تجهيز Xray-core: {e}", "❌")
        sys.exit(1)

    # --- ب. جلب الإعدادات ---
    log_header("المرحلة 2: جلب الإعدادات")
    configs = fetch_configs(CONFIGS_URL)
    if not configs:
        log("لا توجد إعدادات للاختبار", "❌")
        OUTPUT_FILE.write_text("", encoding="utf-8")
        sys.exit(0)

    # --- ج. تجهيز المُختبر ---
    log_header("المرحلة 3: تجهيز المُختبر")
    tester = ConnectionTester(
        vendor_path=str(project_root / "vendor"),
        core_engine_path=str(project_root / "core_engine"),
    )
    log("المُختبر جاهز", "✅")

    # --- د. الاختبار ---
    log_header("المرحلة 4: اختبار الإعدادات")
    working: List[str] = []
    total = len(configs)

    for i, cfg in enumerate(configs, 1):
        tag = cfg.split("#")[-1] if "#" in cfg else cfg[:60]
        log(f"[{i}/{total}] ← {tag}", "🔎")

        if test_config(cfg, tester):
            working.append(cfg)
            log(f"[{i}/{total}] ✅ يعمل — تمت إضافته للقائمة", "★")
        else:
            log(f"[{i}/{total}] ❌ لا يعمل", "✗")

    # --- هـ. الحفظ ---
    log_header("المرحلة 5: حفظ النتائج")
    if working:
        OUTPUT_FILE.write_text("\n".join(working) + "\n", encoding="utf-8")
        log(f"تم حفظ {len(working)}/{total} إعداد عامل فـ {OUTPUT_FILE}", "✅")
    else:
        OUTPUT_FILE.write_text("", encoding="utf-8")
        log(f"لم يعمل أي إعداد — تم تفريغ {OUTPUT_FILE}", "⚠️")

    log_header("انتهى بنجاح")


if __name__ == "__main__":
    main()
