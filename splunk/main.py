#!/usr/bin/env python3
import sys
import pprint
from functions import *


#cfg = load_config("/opt/splunk/bin/scripts/config.ini")
cfg = load_config("config.ini")
# Telegram config
BOT_TOKEN = cfg["telegram"]["bot_token"]
CHAT_ID = cfg["telegram"]["chat_id"]
CF_TOKEN = cfg["cloudflare"]["api_token"]

# Load whitelist (nếu không có file thì vẫn chạy với danh sách mặc định)
WHITELIST = load_whitelist()
# Log để kiểm tra Splunk truyền tham số gì
with open("/opt/splunk/bin/scripts/script_debug.log", "a") as f:
    f.write(f"\nARGS ({len(sys.argv)}): {sys.argv}\n")

if len(sys.argv) < 8:
    sys.exit("Not enough arguments for this script")

PROJECT = sys.argv[4]
RESULT_FILE = sys.argv[8]


# Get Threshold from config
project_setting = PROJECT.split('_')[0].lower()+ "_threshold";
THRESHOLD=10000
## Default add domain in expression
DOMAININRULE = True

if PROJECT in cfg:
   THRESHOLD = int(cfg[PROJECT]['threshold'])
   DOMAIN =  cfg[PROJECT]['domain']
   DOMAININRULE = cfg[PROJECT]['domaininrule']
   # Array ip block
   top_ips = parse_result_file(RESULT_FILE, WHITELIST,THRESHOLD,DOMAIN)
else:
    print("not in cfg")
    try:
        THRESHOLD=int(cfg["project"][project_setting])
    except ValueError as e:
        print(f"Can't get Threshold {e}")
        ## DO NOT ACTION IF CAN'T GET THRESHOLD
        sys.exit(1) 
    # Array ip block
    top_ips = parse_result_file(RESULT_FILE, WHITELIST,THRESHOLD) 

pprint.pprint(top_ips)
  
if not top_ips:   # kiểm tra list rỗng
    print("⚠️ Không có IP nào, thoát chương trình.")
    sys.exit(0)
message = build_message(PROJECT, top_ips)
## Bloking process

for ip, domain, hit in top_ips:
    ## temp for debug
    #domain="abc.sgbgame.win"
   # print(domain)
    print(f"{ip} - {domain} - {hit}")
    block_ip_on_domain_new(CF_TOKEN, domain, ip,BOT_TOKEN,CHAT_ID,"Auto",DOMAININRULE)

#send_telegram_message(BOT_TOKEN, CHAT_ID, message)
