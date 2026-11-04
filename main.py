import os
import sys
import urllib.request
from pathlib import Path
from typing import List

from python_v2ray.downloader import BinaryDownloader
from python_v2ray.config_parser import parse_uri
from python_v2ray.tester import ConnectionTester

# ============================================================
# 1. الإعدادات
# ============================================================

CONFIGS_URL = "https://github.com/williamnecoo1-pixel/testrw/raw/refs/heads/main/reality_configs.txt"

# الروابط الثلاثة التي طلبتها + رابط إضافي من عندي (Microsoft)
TEST_URLS = [
    "https://www.google.com/generate_204",                 # Google
    "http://cp.cloudflare.com/generate_204",               # Cloudflare
    "http://captive.apple.com/hotspot-detect.html",        # Apple
    "http://edge-http.microsoft.com/captiveportal/generate_204",  # Microsoft (إضافة)
]

OUTPUT_FILE = Path("working.txt")

# ============================================================
# 2. جلب الإعدادات من الرابط البعيد
# ============================================================

def fetch_configs(url: str) -> List[str]:
    """يجلب محتوى ملف الإعدادات ويعيد قائمة بالروابط (سطر لكل رابط)."""
    print(f"[*] جلب الإعدادات من: {url}")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode("utf-8")
    except Exception as e:
        print(f"[!] فشل جلب الإعدادات: {e}")
        return []

    configs = [
        line.strip()
        for line in content.splitlines()
        if line.strip().startswith(("vless://", "vmess://", "trojan://", "ss://"))
    ]
    print(f"[+] تم العثور على {len(configs)} إعداد.")
    return configs

# ============================================================
# 3. اختبار إعداد واحد مقابل جميع نقاط النهاية
# ============================================================

def test_config(config_uri: str, tester: ConnectionTester) -> bool:
    """
    يختبر إعداداً واحداً مقابل جميع نقاط النهاية.
    يعتبر الإعداد \"عاملاً\" إذا نجح في اختبار واحد على الأقل.
    """
    parsed = parse_uri(config_uri)
    if not parsed:
        return False

    for url in TEST_URLS:
        try:
            results = tester.test_uris([parsed], test_url=url)
            for res in results:
                if res.get("status") == "success" and res.get("ping_ms", -1) >= 0:
                    print(f"    [✓] نجح مع {url} (زمن الاستجابة: {res['ping_ms']} ms)")
                    return True
        except Exception as e:
            print(f"    [!] خطأ أثناء الاختبار مع {url}: {e}")

    return False

# ============================================================
# 4. الدالة الرئيسية
# ============================================================

def main() -> None:
    # --- أ. تنزيل/التأكد من وجود Xray-core ---
    project_root = Path(".")
    downloader = BinaryDownloader(project_root)
    try:
        downloader.ensure_all()
        print("[✓] Xray-core جاهز.")
    except Exception as e:
        print(f"[!] فشل تجهيز Xray-core: {e}")
        sys.exit(1)

    # --- ب. جلب الإعدادات ---
    configs = fetch_configs(CONFIGS_URL)
    if not configs:
        print("[!] لا توجد إعدادات للاختبار. إنهاء.")
        sys.exit(1)

    # --- ج. تجهيز المُختبر ---
    tester = ConnectionTester(
        vendor_path=str(project_root / "vendor"),
        core_engine_path=str(project_root / "core_engine"),
    )

    # --- د. اختبار كل إعداد وحفظ العامل منها ---
    working_configs: List[str] = []
    total = len(configs)

    for idx, config in enumerate(configs, 1):
        tag = config.split("#")[-1] if "#" in config else config[:50]
        print(f"\n[{idx}/{total}] اختبار: {tag}")

        if test_config(config, tester):
            working_configs.append(config)
            print(f"    [★] الإعداد يعمل! تمت إضافته إلى {OUTPUT_FILE}")
        else:
            print(f"    [✗] الإعداد لا يعمل.")

    # --- هـ. كتابة النتائج ---
    if working_configs:
        OUTPUT_FILE.write_text("\n".join(working_configs) + "\n", encoding="utf-8")
        print(f"\n[✓] تم حفظ {len(working_configs)} إعداد عامل في {OUTPUT_FILE}")
    else:
        # ملف فارغ حتى لا يبقى ملف قديم من تشغيل سابق
        OUTPUT_FILE.write_text("", encoding="utf-8")
        print(f"\n[!] لم يعمل أي إعداد. تم تفريغ {OUTPUT_FILE}.")

if __name__ == "__main__":
    main()
