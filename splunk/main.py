#!/usr/bin/env python3
import sys
import pprint
from functions import *


cfg = load_config("config.ini")

# Telegram config
BOT_TOKEN = cfg["telegram"]["bot_token"]
CHAT_ID = cfg["telegram"]["chat_id"]
CF_TOKEN = cfg["cloudflare"]["api_token"]

# Load whitelist (nếu không có file thì vẫn chạy với danh sách mặc định)
WHITELIST = load_whitelist()
# Log để kiểm tra Splunk truyền tham số gì
with open("/opt/splunk/var/log/splunk/script_debug.log", "a") as f:
    f.write(f"\nARGS ({len(sys.argv)}): {sys.argv}\n")

if len(sys.argv) < 8:
    sys.exit("Not enough arguments passed by Splunk")

PROJECT = sys.argv[4]
RESULT_FILE = sys.argv[8]


# Array ip block
top_ips = parse_result_file(RESULT_FILE, whitelist=WHITELIST)
message = build_message(PROJECT, top_ips)

## Bloking ptocess
for ip, domain, hit in top_ips:
    ## temp for debug
    domain="abc.sgbgame.win"
    block_ip_on_domain(CF_TOKEN, domain, ip)
# Block IP 1.2.3.4 chỉ trên domain example.com
#block_ip_on_domain(CF_TOKEN, "abc.sgbgame.win", "168.93.213.19")


send_telegram_message(BOT_TOKEN, CHAT_ID, message)
