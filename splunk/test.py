#!/usr/bin/env python3
import sys
import pprint
from functions import *
cfg = load_config("/opt/splunk/bin/scripts/config.ini")
#cfg = load_config("config.ini")
BOT_TOKEN = cfg["telegram"]["bot_token"]
CHAT_ID = cfg["telegram"]["chat_id"]
CF_TOKEN = cfg["cloudflare"]["api_token"]
#zone_id=get_zone_id_from_domain("123","sgbgame.win")
#print(zone_id)
# Chuỗi expression
expression = '(http.host eq "bordergw.api-inovated.com" and ip.src eq 171.251.152.159) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.189.117.242) or ...'
expression = '(http.host eq "bordergw.api-inovated.com" and ip.src eq 171.251.152.159) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.189.117.242) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 27.67.120.49) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.199.32.195) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.153.78.236) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.185.45.218) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.180.151.71) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.207.38.166) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.177.108.218) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.156.92.240) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.156.91.8) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 171.234.10.66) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.207.37.61) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.177.108.205) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 202.158.247.116) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 160.250.166.239) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.156.90.123) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.207.39.71) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 157.66.252.99) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.147.185.209) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 2401:d800:9db1:3843:6493:c87f:2d6c:4dcd) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 171.234.10.91) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.185.47.58) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.114.105.162) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.149.13.76) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.177.109.137) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 180.214.238.117) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.185.104.130) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.177.108.213) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.180.152.236) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 180.214.236.125) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.190.81.60) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.185.104.200) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 42.1.84.14) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 112.213.87.196) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.141.138.120) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.177.109.32) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.185.76.151) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 171.253.233.51) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 115.72.73.161) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 171.234.10.107) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 115.73.200.96) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.185.40.193) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 27.67.120.205) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.185.41.60) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.185.76.15) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 113.185.43.82) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 27.67.121.152) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 27.67.121.225) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.199.32.103) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 59.153.238.156) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 14.225.51.146) or (http.host eq "bordergw.api-inovated.com" and ip.src eq 103.156.93.74)'
# 1️⃣ Số ký tự
num_chars = len(expression)
print("Số ký tự:", num_chars)

# 2️⃣ Kích thước byte (UTF-8)
num_bytes = len(expression.encode('utf-8'))
print("Kích thước (byte UTF-8):", num_bytes)
sys.exit(1)
try:
	cf_rename_rule_by_name("api-inovated.com",CF_TOKEN,"AutoBlock-CustomRule1","AutoBlock-CustomRule2")
	#create_firewall_rule("api-inovated.com",CF_TOKEN,"AutoBlock-CustomRule1")
	create_firewall_rule(domain,cf_token,"AutoBlock-CustomRule",updated_expr)
	msg = "ok"
	with open("test.log", "a") as f:
     		f.write("ok")
except Exception as e:
	with open("test.log", "a") as f:
        	f.write("e")
	send_telegram_message("8024472794:AAEtN4Ccf722_Fxrw5ak7jDuxsJUG8hJXZ8", 7720672433, e)
#express=get_expression_from_rule_name("sgbgame.win","123")
#print(express)
