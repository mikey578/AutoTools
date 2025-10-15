#!/usr/bin/env python3
import sys
from functions import (
    load_whitelist,
    parse_result_file,
    build_message,
    send_telegram_message
)
from functions import *
# Telegram config
BOT_TOKEN = "8024472794:AAEtN4Ccf722_Fxrw5ak7jDuxsJUG8hJXZ8"
CHAT_ID = "7720672433"

# Load whitelist (nếu không có file thì vẫn chạy với danh sách mặc định)
WHITELIST = load_whitelist()
# Log để kiểm tra Splunk truyền tham số gì
with open("/opt/splunk/var/log/splunk/script_debug.log", "a") as f:
    f.write(f"\nARGS ({len(sys.argv)}): {sys.argv}\n")

if len(sys.argv) < 8:
    sys.exit("Not enough arguments passed by Splunk")

PROJECT = sys.argv[4]
RESULT_FILE = sys.argv[8]

top_ips = parse_result_file(RESULT_FILE, whitelist=WHITELIST)
message = build_message(PROJECT, top_ips)


CF_TOKEN = "_O3S6AoQg7PkgqoA1NwHi0Ea1TGE0e7j97WHbIgu"

# Block IP 1.2.3.4 chỉ trên domain example.com
block_ip_on_domain(CF_TOKEN, "abc.sgbgame.win", "168.93.213.19")


send_telegram_message(BOT_TOKEN, CHAT_ID, message)
[root@ops-general-monitoring scripts]# cat functions.py 
#!/usr/bin/env python3
import os
import gzip
import csv
import re
import requests
import ipaddress
from datetime import datetime



# -------------------------------
# IP / Range Whitelist functions
# -------------------------------

def load_whitelist(path="/opt/splunk/bin/scripts/whitelist.txt"):
    """
    Đọc danh sách whitelist IP/range từ file (mỗi dòng 1 IP hoặc CIDR).
    """
    whitelist = []
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    whitelist.append(line)
    return whitelist

def is_ip_whitelisted(ip, whitelist):
    """
    Kiểm tra IP có nằm trong whitelist không.
    Hỗ trợ cả IP đơn lẻ và CIDR range.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in whitelist:
            try:
                if ip_obj in ipaddress.ip_network(net, strict=False):
                    return True
            except ValueError:
                if ip == net:
                    return True
    except ValueError:
        pass
    return False

# -------------------------------
# Parse result file
# -------------------------------
def parse_result_file(result_file, whitelist=None):
    """
    Đọc file Splunk CSV.GZ, lọc IP theo threshold và whitelist.
    """
    if whitelist is None:
        whitelist = []

    results = []
    THRESHOLD=1000
    try:
        with gzip.open(result_file, 'rt', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)  # bỏ header
            for row in reader:
                if len(row) < 3:
                    continue
                ip = row[0].replace('"', '').strip()
                project = row[1].replace('"', '').strip()
                try:
                    hits = int(row[2].replace('"', '').strip())
                except ValueError:
                    continue

                if hits > THRESHOLD and not is_ip_whitelisted(ip, whitelist):
                    results.append((ip, project, hits))
    except FileNotFoundError:
        return []

    return results

# -------------------------------
# Message Builder
# -------------------------------

def build_message(project, top_ips):
    """
    Tạo nội dung tin nhắn Telegram cảnh báo.
    """
    if not top_ips:
        top_ips_str = "(no result or all IPs whitelisted)"
    else:
        top_ips_str = "\n".join(
            f"{p}:\n  {ip:<18} : {hits} hits"
            for ip, p, hits in top_ips
        )

    return (
        f"*Splunk Alert:* *{project}*\n"
        f"*Time:* {datetime.now():%Y-%m-%d %H:%M:%S}\n"
        f"*Top IPs:*\n"
        f"```\n{top_ips_str}\n```"
    )

# -------------------------------
# Telegram Sender
# -------------------------------

def send_telegram_message(bot_token, chat_id, message):
    """
    Gửi tin nhắn tới Telegram qua Bot API.
    """
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "parse_mode": "Markdown",
        "text": message
    }

    try:
        response = requests.post(url, data=payload, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"[Telegram Error] {e}")


def format_args(args):
    """Trả về chuỗi liệt kê toàn bộ tham số."""
    return "\n".join([f"Param {i} = {arg}" for i, arg in enumerate(args, start=1)])

#------------------------------
# CF define functions
# ----------------------------
def is_ip_or_cidr(value):
    ip4 = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    ipv6 = r'^([0-9a-fA-F:]+)(/\d{1,3})?$'
    return bool(re.match(ip4, value)) or bool(re.match(ipv6, value))


def is_domain(value):
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return bool(re.match(domain_pattern, value))


def get_zone_id_from_domain(cf_token, domain, account_id=None, timeout=10):
    """
    Lấy zone_id của domain qua Cloudflare API.
    """
    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json",
    }
    parts = domain.strip().lower().split(".")
    if len(parts) > 2:
        root_domain = ".".join(parts[-2:])  # lấy 2 phần cuối
        print(f"ℹ️ {domain} là subdomain, dùng zone ID của {root_domain}")
    else:
        root_domain = domain
    params = {"name": root_domain}
    if account_id:
        params["account.id"] = account_id

    url = "https://api.cloudflare.com/client/v4/zones"

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        data = resp.json()
    except Exception as e:
        print(f"[CF] Lỗi khi gọi API lấy zone id cho {domain}: {e}")
        return None

    if resp.status_code != 200 or not data.get("success"):
        print(f"[CF] Không lấy được zone id cho {domain}: {data}")
        return None

    results = data.get("result", [])
    if not results:
        print(f"[CF] Không tìm thấy zone cho domain {domain}")
        return None

    return results[0].get("id")


def block_ip_on_domain(cf_token, domain, ip, description="Auto-block"):
    """
    Chặn 1 IP chỉ khi truy cập domain cụ thể trên Cloudflare Firewall Rule.
    """
    if not is_domain(domain):
        print(f"❌ Domain không hợp lệ: {domain}")
        return False
    if not is_ip_or_cidr(ip):
        print(f"❌ IP không hợp lệ: {ip}")
        return False

    zone_id = get_zone_id_from_domain(cf_token, domain)
    if not zone_id:
        print(f"❌ Không lấy được Zone ID cho {domain}")
        return False

    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json"
    }
    description=description + "_" + domain + "_" + ip
    # Rule expression: chặn IP chỉ trên domain này
    expression = f'(http.host eq "{domain}") and (ip.src eq {ip})'
    ### Check trung
    api_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"

    # 🔍 Kiểm tra xem rule này đã tồn tại chưa
    try:
        existing = requests.get(api_url, headers=headers, timeout=15).json()
        if existing.get("success"):
            for rule in existing.get("result", []):
                filt = rule.get("filter", {})
                if filt.get("expression") == expression:
                    print(f"⚠️ Rule chặn {ip} trên domain {domain} đã tồn tại (rule_id={rule['id']})")
                    return True
    except Exception as e:
        print(f"⚠️ Không thể kiểm tra rule tồn tại: {e}")
    
   # api_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
    payload = [{
        "action": "block",
        "description": description,
        "filter": {
            "expression": expression,
            "paused": False
        }
    }]

    try:
        resp = requests.post(api_url, headers=headers, json=payload, timeout=15)
        data = resp.json()
        if resp.status_code in (200, 201) and data.get("success"):
            print(f"✅ Đã block IP {ip} trên domain {domain} (zone {zone_id})")
            return True
        else:
            print(f"❌ Lỗi block IP {ip} trên {domain}: {data}")
            return False
    except Exception as e:
        print(f"⚠️ Exception khi block IP {ip} trên {domain}: {e}")
        return False
