#!/usr/local/bin/python3
import os
import gzip
import json
import csv
import re
import pprint
import requests # type: ignore
import requests as rq
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
     Read whitelist IP/range from file (IP/CIDR).
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
	check ip whitelist
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
	Read file from splunk
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
    	Build message
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
	Send message
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
    """debug"""
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
    #return bool(re.match(domain_pattern, value))
    return True;

def get_zone_id_from_domain(cf_token, domain, account_id=None, timeout=10):
    """
	get zone from domain/sub
    """
    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json",
    }
    parts = domain.strip().lower().split(".")
    if len(parts) > 2:
        root_domain = ".".join(parts[-2:])  # lấy 2 phần cuối
        print(f"ℹ️ {domain} is subdomain, zone ID is {root_domain}")
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
        print(f"[CF] Can't get zone id from {domain}: {e}")
        return None

    if resp.status_code != 200 or not data.get("success"):
        print(f"[CF] Can't get zone id from {domain}: {data}")
        return None

    results = data.get("result", [])
    if not results:
        print(f"[CF] Can't get Zone id from domain {domain}")
        return None

    return results[0].get("id")


def block_ip_on_domain(cf_token, domain, ip, bot_token,chat_id, description="Auto"):
    """
	block ip access domain
    """
    msg=""
    if not is_domain(domain):
        send_telegram_message(bot_token, chat_id, "Wrong domain: " + domain)
        print(f"❌ DWrong domain: {domain}")
        return False
    if not is_ip_or_cidr(ip):
        send_telegram_message(bot_token, chat_id, "Wrong IP: " + ip)
        print(f"❌ IWrong IP: {ip}")
        return False

    zone_id = get_zone_id_from_domain(cf_token, domain)
    if not zone_id:
        send_telegram_message(bot_token, chat_id, "Can't get zone id from  " + domain)
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
                    send_telegram_message(bot_token, chat_id,f"IP:" + ip + " Blocked access on domain:" + domain )
                    return True
    except Exception as e:
        send_telegram_message(bot_token, chat_id, "Can't get rule: " + e)
    
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
            send_telegram_message(bot_token, chat_id, "Blocked IP: " + ip +  " access domain: " +  domain)
            return True
        else:
            send_telegram_message(bot_token, chat_id, "error block IP " + ip +  " on "  + domain + ": " + data)
            return False
    except Exception as e:
        send_telegram_message(bot_token, chat_id, "Exception block IP" +  ip + " on " + domain + ":" + e)
        return False


##### Update Rule 
def block_ip_on_domain_new(cf_token, domain, ip, bot_token, chat_id, description="Auto"):
    """
    """
    if not is_domain(domain):
        msg = f"Wrong domain: {domain}"
        send_telegram_message(bot_token, chat_id, msg)
        return False
    if not is_ip_or_cidr(ip):
        msg = f"Wrong IP:  {ip}"
        send_telegram_message(bot_token, chat_id, msg)
        return False

    zone_id = get_zone_id_from_domain(cf_token, domain)
    if not zone_id:
        msg = "Zone id not found"
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
        # 🔍get current rule
        resp = requests.get(api_rules, headers=headers, timeout=15)
        rules = resp.json().get("result", []) if resp.ok else []

        # 🔍find rule have description start with  AutoBlock-CustomRule
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
                msg = f"IP: {ip} is Blocked on domain {domain}"
                send_telegram_message(bot_token, chat_id, msg)
                return True

            # 🔁build new expression
            updated_expr = f"{old_expr} or {new_expr}" if old_expr else new_expr
            create_firewall_rule("sgbgame.win",cf_token,"AutoBlock-CustomRule1")
            # Update old rule
            update_filter_payload = {
                "id": old_filter_id,
                "expression": updated_expr,
                "paused": False,
                "description": "AutoBlock-CustomRule"
            }
            try:
              upd_filter = rq.put(f"{api_filters}/{old_filter_id}",headers={**headers, "Content-Type": "application/json"},data=json.dumps(update_filter_payload),timeout=15).json()
            except Exception as e:
               msg = f"Can't update Cloudflare: {e} on {domain}"
               send_telegram_message(bot_token, chat_id, msg)
            if upd_filter.get("success"):
                msg = f"Blocked IP: {ip} access {domain} on rule AutoBlock-CustomRule"
                send_telegram_message(bot_token, chat_id, msg)
                print(msg)
                return True
            else:
                msg = f"Can't update filter: {upd_filter} on {domain}"
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
                msg = f"❌Can't create filter: {new_filter}"
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
                msg = f"✅Create rule AutoBlock-CustomRule and block IP {ip} access {domain}"
                send_telegram_message(bot_token, chat_id, msg)
                return True
            else:
                msg = f"Can't create rule:  {r}"
                send_telegram_message(bot_token, chat_id, msg)
                print(msg)
                return False

    except Exception as e:
        msg = f"Can't update Cloudflare: {e} on {domain}"
        send_telegram_message(bot_token, chat_id, msg)
        return False

def get_expression_from_rule_name(domain, api_token, rule_name="AutoBlock-CustomRule"):
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    zone_id=get_zone_id_from_domain(api_token,domain)
    # 1️⃣ Lấy danh sách firewall rules
    api_rules = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
    resp = requests.get(api_rules, headers=headers, timeout=15).json()
    if not resp.get("success"):
        print(f"❌ Can't fetch rules: {resp}")
        return None

    # 2️⃣ Tìm rule theo tên
    target_rule = next((r for r in resp["result"] if r["description"] == rule_name), None)
    if not target_rule:
        print(f"❌ Rule '{rule_name}' not found")
        return None

    # 3️⃣ Lấy filter id
    filter_id = target_rule.get("filter", {}).get("id")
    if not filter_id:
        print(f"❌ Rule '{rule_name}' has no filter attached")
        return None

    # 4️⃣ Get filter detail
    api_filters = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/filters/{filter_id}"
    filter_resp = requests.get(api_filters, headers=headers, timeout=15).json()
    if not filter_resp.get("success"):
        print(f"❌ Can't fetch filter: {filter_resp}")
        return None

    expression = filter_resp["result"]["expression"]
    print(f"✅ Expression for rule '{rule_name}': {expression}")
    return expression

def create_firewall_rule(domain, api_token, rule_name="AutoBlock-CustomRule",expression='ip.src == 0.1.2.3 ', action="block"):
    """
    Create Firewall Rule (API old)  filters + rules

    Args:
        zone_id: Zone ID Cloudflare
        api_token: API Token ( Permission Zone Firewall Services:Edit)
        expression: Cloudflare filter expression
        rule_name: 
        action: block | allow | challenge | js_challenge | log
    """
    zone_id=get_zone_id_from_domain(api_token,domain)
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    # 1️⃣ Create filter
    api_filters = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/filters"
    filter_payload = [{
        "expression": expression,
        "paused": False,
        "description": rule_name
    }]
    resp = requests.post(api_filters, headers=headers, json=filter_payload, timeout=15)
    new_filter = resp.json()

    if not new_filter.get("success"):
        print(f"❌ Can't create filter: {new_filter}")
        return None

    filter_id = new_filter["result"][0]["id"]
    print(f"✅ Created filter: {filter_id}")

    # 2️⃣ Create Firewall Rule on filter 
    api_rules = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
    rule_payload = [{
        "filter": {"id": filter_id},
        "action": action,
        "description": rule_name
    }]
    rule_resp = requests.post(api_rules, headers=headers, json=rule_payload, timeout=15)
    rule_data = rule_resp.json()

    if rule_resp.status_code != 200 or not rule_data.get("success"):
        print(f"❌ Can't create rule: {rule_data}")
        return None

    print(f"✅ Created firewall rule: {rule_data['result'][0]['id']}")
    return rule_data['result'][0]['id']