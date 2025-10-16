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


# Get Threshold from config
project_setting = PROJECT.split('_')[0].lower()+ "_threshold";
THRESHOLD=10000
try:
    THRESHOLD=int(cfg["project"][project_setting])
except ValueError as e:
    print(f"Can't get Threshold {e}")
    ## DO NOT ACTION IF CAN'T GET THRESHOLD
    sys.exit(1) 
    
# Array ip block
top_ips = parse_result_file(RESULT_FILE, WHITELIST,THRESHOLD)
message = build_message(PROJECT, top_ips)
print(123)
pprint.pprint(top_ips)
## Bloking ptocess
for ip, domain, hit in top_ips:
    ## temp for debug
    domain="abc.sgbgame.win"
    print(domain)
    block_ip_on_domain_new(CF_TOKEN, domain, ip,BOT_TOKEN,CHAT_ID)

#send_telegram_message(BOT_TOKEN, CHAT_ID, message)
