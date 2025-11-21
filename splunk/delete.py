import requests
import sys
import time
import json
# Thay bằng token và zone của bạn
API_TOKEN = "qp613CjQ07zaE28jWKmfdvUTT0wGjTvNl7jtwiBi"
ZONE_ID = "ee3c413297ba0dde31034ced78343b42"
RULE_NAME_TO_DELETE = "AutoBlock-CustomRule1"

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

# 1. Lấy danh sách tất cả các WAF / Firewall rules
url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/rules?per_page=1000"
response = requests.get(url, headers=headers)
response.raise_for_status()

rules = response.json().get("result", [])
# In toàn bộ response JSON, đẹp hơn với indent
try:
    data = response.json()
    print("Response JSON:")
    print(json.dumps(data, indent=4))
except Exception as e:
    print("Không thể parse JSON:", e)
    print("Raw response:", response.text)
# 2. Tìm những rule có tên giống RULE_NAME_TO_DELETE
rules_to_delete = [rule for rule in rules if rule.get("description") == RULE_NAME_TO_DELETE]
# 3. Xoá từng rule
for rule in rules_to_delete:
    rule_id = rule["id"]
    del_url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/rules/{rule_id}"
    del_resp = requests.delete(del_url, headers=headers)
    if del_resp.status_code == 200:
        print(f"Deleted rule {RULE_NAME_TO_DELETE} (ID: {rule_id})")
    else:
        print(f"Failed to delete rule {rule_id}: {del_resp.text}")
print("Done.")
