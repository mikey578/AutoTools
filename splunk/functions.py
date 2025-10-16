#!/usr/bin/env python3
import os
import gzip
import csv
import re
import pprint
import requests # type: ignore
import ipaddress
from datetime import datetime
import configparser
from pathlib import Path

#----------------------
# Load config from file
#----------------------
def load_config(path: str) -> dict:
    """
    Load .ini config file and return a nested dict.
    Example:
        cfg['telegram']['bot_token']
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    parser = configparser.ConfigParser()
    parser.optionxform = str  # giữ nguyên chữ hoa/thường
    parser.read(config_path, encoding="utf-8")

    cfg = {section: dict(parser.items(section)) for section in parser.sections()}
    return cfg


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
def parse_result_file(result_file, whitelist=None,threshold=10000):
    """
    Đọc file Splunk CSV.GZ, lọc IP theo threshold và whitelist.
    """
    if whitelist is None:
        whitelist = []

    results = []
    THRESHOLD=threshold
    try:
        with gzip.open(result_file, 'rt', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)  # bỏ header
            for row in reader:
                if len(row) < 3:
                    continue
                ip = row[0].replace('"', '').strip()
                domain = row[1].replace('"', '').strip()
                try:
                    hits = int(row[2].replace('"', '').strip())
                except ValueError:
                    continue

                if hits > THRESHOLD and not is_ip_whitelisted(ip, whitelist):
                    results.append((ip, domain, hits))
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


def block_ip_on_domain(cf_token, domain, ip, bot_token,chat_id, description="Auto"):
    """
    Chặn 1 IP chỉ khi truy cập domain cụ thể trên Cloudflare Firewall Rule.
    """
    msg=""
    if not is_domain(domain):
        send_telegram_message(bot_token, chat_id, "Domain không hợp lệ: " + domain)
        print(f"❌ Domain không hợp lệ: {domain}")
        return False
    if not is_ip_or_cidr(ip):
        send_telegram_message(bot_token, chat_id, "IP không hợp lệ: " + ip)
        print(f"❌ IP không hợp lệ: {ip}")
        return False

    zone_id = get_zone_id_from_domain(cf_token, domain)
    if not zone_id:
        send_telegram_message(bot_token, chat_id, "Không lấy được Zone ID cho  " + domain)
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
                    send_telegram_message(bot_token, chat_id,"Rule chặn "+ ip + " trên domain " + domain + "đã tồn tại" )
                    print(f"⚠️ Rule chặn {ip} trên domain {domain} đã tồn tại (rule_id={rule['id']})")
                    return True
    except Exception as e:
        send_telegram_message(bot_token, chat_id, "Không thể kiểm tra rule tồn tại: " + e)
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
            send_telegram_message(bot_token, chat_id, "Đã block IP " + ip +  " trên domain " +  domain + " zone " + zone_id)
            print(f"✅ Đã block IP {ip} trên domain {domain} (zone {zone_id})")
            return True
        else:
            send_telegram_message(bot_token, chat_id, "Lỗi block IP " + ip +  " trên "  + domain + ": " + data)
            print(f"❌ Lỗi block IP {ip} trên {domain}: {data}")
            return False
    except Exception as e:
        send_telegram_message(bot_token, chat_id, "Exception khi block IP" +  ip + " trên " + domain + ":" + e)
        print(f"⚠️ Exception khi block IP {ip} trên {domain}: {e}")
        return False


##### Update Rule 
def block_ip_on_domain_new(cf_token, domain, ip, bot_token, chat_id, description="Auto"):
    """
    ✅ Cập nhật IP vào rule có tên 'AutoBlock-CustomRule' (duy nhất trên zone)
    ✅ Không tạo thêm unused filter
    ✅ Nếu chưa có rule này → tự tạo mới
    """
    if not is_domain(domain):
        msg = f"❌ Domain không hợp lệ: {domain}"
        send_telegram_message(bot_token, chat_id, msg)
        print(msg)
        return False
    if not is_ip_or_cidr(ip):
        msg = f"❌ IP không hợp lệ: {ip}"
        send_telegram_message(bot_token, chat_id, msg)
        print(msg)
        return False

    zone_id = get_zone_id_from_domain(cf_token, domain)
    if not zone_id:
        msg = f"❌ Không lấy được Zone ID cho {domain}"
        send_telegram_message(bot_token, chat_id, msg)
        print(msg)
        return False

    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json"
    }

    api_rules = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
    api_filters = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/filters"

    try:
        # 🔍 Lấy danh sách rule hiện có
        resp = requests.get(api_rules, headers=headers, timeout=15)
        rules = resp.json().get("result", []) if resp.ok else []

        # 🔍 Tìm rule có description bắt đầu bằng AutoBlock-CustomRule
        target_rule = None
        for r in rules:
            desc = r.get("description", "")
            if desc == "AutoBlock-CustomRule":
                target_rule = r
                break

        new_expr = f'(http.host eq "{domain}"  and ip.src eq {ip})'

        if target_rule:
            rule_id = target_rule["id"]
            filt = target_rule.get("filter", {})
            old_expr = filt.get("expression", "")
            old_filter_id = filt.get("id")

            if new_expr in old_expr:
                msg = f"IP {ip} đã tồn tại trong rule AutoBlock CustomRule trên {domain}"
                send_telegram_message(bot_token, chat_id, msg)
                print(msg)
                return True

            # 🔁 Gộp thêm IP vào cùng biểu thức cũ
            updated_expr = f"{old_expr} or {new_expr}" if old_expr else new_expr

            # ⚙️ Cập nhật lại filter cũ thay vì tạo filter mới → tránh unused
            update_filter_payload = {
                "id": old_filter_id,
                "expression": updated_expr,
                "paused": False,
                "description": "AutoBlock-CustomRule"
            }

            upd_filter = requests.put(
                f"{api_filters}/{old_filter_id}", headers=headers, json=update_filter_payload, timeout=15
            ).json()

            if upd_filter.get("success"):
                msg = f"Đã thêm IP {ip} vào filter {old_filter_id} của rule AutoBlock-CustomRule"
                send_telegram_message(bot_token, chat_id, msg)
                print(msg)
                return True
            else:
                msg = f"Lỗi cập nhật filter: {upd_filter}"
                send_telegram_message(bot_token, chat_id, msg)
                print(msg)
                return False

        else:
            # 🚀 Chưa có rule AutoBlock-CustomRule → tạo mới
            filter_payload = [{
                "expression": new_expr,
                "paused": False,
                "description": "AutoBlock-CustomRule"
            }]
            new_filter = requests.post(api_filters, headers=headers, json=filter_payload, timeout=15).json()

            if not new_filter.get("success"):
                msg = f"❌ Lỗi tạo filter: {new_filter}"
                send_telegram_message(bot_token, chat_id, msg)
                print(msg)
                return False

            new_filter_id = new_filter["result"][0]["id"]

            rule_payload = [{
                "action": "block",
                "description": "AutoBlock-CustomRule",
                "filter": {"id": new_filter_id}
            }]
            r = requests.post(api_rules, headers=headers, json=rule_payload, timeout=15).json()

            if r.get("success"):
                msg = f"✅ Đã tạo rule AutoBlock-CustomRule và chặn IP {ip} trên {domain}"
                send_telegram_message(bot_token, chat_id, msg)
                print(msg)
                return True
            else:
                msg = f"❌ Lỗi tạo rule mới: {r}"
                send_telegram_message(bot_token, chat_id, msg)
                print(msg)
                return False

    except Exception as e:
        msg = f"⚠️ Exception khi xử lý Cloudflare: {e}"
        send_telegram_message(bot_token, chat_id, msg)
        print(msg)
        return False
