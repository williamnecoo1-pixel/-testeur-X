import urllib.request
import base64
import json
import re
import urllib.parse

# ================== الإعدادات ==================
SOURCES = [
"https://github.com/williamnecoo1-pixel/-testeur-X/raw/refs/heads/main/working.txt",
]

ALLOWED_PROTOCOLS = ["vless", "vmess", "trojan"]
ALLOWED_PORT = 443
ALLOWED_TRANSPORT = "xhttp"
FORCED_MODE = "packet-up"      # ✅ الوضع اللي بغينا نفرضوه
FORCED_IP   = "104.18.37.127"  # ✅ الـ IP اللي غادي نفرضو فـ add / netloc

# ================== دوال مساعدة للتشفير ==================
def b64_decode(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    s += '=' * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def b64_encode(s):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def fetch_url(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return ""

# ================== دوال المعالجة ==================
def process_vless_trojan(link):
    try:
        parsed = urllib.parse.urlparse(link)

        port = parsed.port or 443
        if port != ALLOWED_PORT:
            return None

        query_dict = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        security = query_dict.get('security', [''])[0].lower()
        if security != 'tls':
            return None

        net_type = query_dict.get('type', query_dict.get('network', ['']))[0].lower()
        if net_type != ALLOWED_TRANSPORT:
            return None

        # ✅ فرض وضع packet-up
        query_dict['mode'] = [FORCED_MODE]

        original_host = parsed.hostname
        if not original_host:
            return None

        # نحافظو على الدومين الأصلي فـ sni/host إلا كانو خاويين
        if 'sni' not in query_dict:
            query_dict['sni'] = [original_host]
        if 'host' not in query_dict:
            query_dict['host'] = [original_host]

        # ✅ نحافظو على userinfo (UUID فـ VLESS / password فـ Trojan)
        userinfo = ""
        if parsed.username is not None:
            userinfo = parsed.username
            if parsed.password:
                userinfo += ":" + parsed.password
            userinfo += "@"

        # ✅ نبدلو الـ host الأصلي بالـ IP المفروض
        new_netloc = f"{userinfo}{FORCED_IP}:{port}"

        new_query = urllib.parse.urlencode(query_dict, doseq=True)

        new_link = urllib.parse.urlunparse((
            parsed.scheme,
            new_netloc,        # ← IP المفروض + port + userinfo
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        return new_link
    except Exception as e:
        print(f"Error processing VLESS/Trojan {link[:30]}: {e}")
        return None

def process_vmess(link):
    try:
        parts = link.split('#', 1)
        b64_part = parts[0].replace("vmess://", "").strip()
        fragment = f"#{parts[1]}" if len(parts) > 1 else ""

        decoded = b64_decode(b64_part)
        if not decoded:
            return None

        obj = json.loads(decoded)

        if int(obj.get("port", 0)) != ALLOWED_PORT:
            return None

        tls_value = obj.get("tls") or obj.get("security") or ""
        if tls_value.lower() != "tls":
            return None

        net_value = obj.get("net") or obj.get("network") or ""
        if net_value.lower() != ALLOWED_TRANSPORT:
            return None

        # ✅ فرض وضع packet-up
        obj["type"] = FORCED_MODE

        original_add = obj.get("add")
        if not original_add:
            return None

        # نحافظو على الدومين الأصلي فـ host/sni
        if not obj.get("host"):
            obj["host"] = original_add
        if not obj.get("sni"):
            obj["sni"] = original_add

        # ✅ نبدلو غير add بالـ IP المفروض (sni/host كيبقاو بالدومين)
        obj["add"] = FORCED_IP

        new_json = json.dumps(obj, separators=(',', ':'))
        new_b64 = b64_encode(new_json)

        return f"vmess://{new_b64}{fragment}"
    except Exception as e:
        print(f"Error processing VMess: {e}")
        return None

# ================== السكريبت الرئيسي ==================
def main():
    all_links = []
    for url in SOURCES:
        content = fetch_url(url)
        if content:
            all_links.extend(content.splitlines())

    valid_configs = set()

    for link in all_links:
        link = link.strip()
        if not link:
            continue

        protocol_match = re.match(r'^(vless|vmess|trojan)://', link, re.IGNORECASE)
        if not protocol_match:
            continue
        protocol = protocol_match.group(1).lower()

        if protocol == "vmess":
            processed = process_vmess(link)
            if processed:
                valid_configs.add(processed)
        elif protocol in ["vless", "trojan"]:
            processed = process_vless_trojan(link)
            if processed:
                valid_configs.add(processed)

    output_file = "reality_configs.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(valid_configs))

    print(f"✅ تم استخراج {len(valid_configs)} كونفيغ XHTTP+TLS (mode=packet-up, IP={FORCED_IP}) بدون تكرار وحفظهم فـ {output_file}")

if __name__ == "__main__":
    main()
