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
