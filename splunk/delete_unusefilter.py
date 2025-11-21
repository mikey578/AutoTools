import requests
API_TOKEN = "qp613CjQ07zaE28jWKmfdvUTT0wGjTvNl7jtwiBi"
ZONE_ID = "ee3c413297ba0dde31034ced78343b42"
headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

# Lấy tất cả rule
rules_url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/rules?per_page=1000"
rules_resp = requests.get(rules_url, headers=headers)
rules_resp.raise_for_status()
rules = rules_resp.json().get("result", [])

# Map rule_id -> status
rule_status_map = {rule["id"]: rule.get("status") for rule in rules}

# Lấy tất cả filter
filters_url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/filters?per_page=1000"
filters_resp = requests.get(filters_url, headers=headers)
filters_resp.raise_for_status()
filters = filters_resp.json().get("result", [])
print(filters)
# Xóa filter không dùng hoặc chỉ dùng bởi rule disabled
for f in filters:
    print(f)
    used_by = f.get("used_by", [])
    if all(rule_status_map.get(rule_id) == "disabled" for rule_id in used_by):
        fid = f["id"]
        del_url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/filters/{fid}"
        del_resp = requests.delete(del_url, headers=headers)
        if del_resp.status_code == 200:
            print(f"Deleted filter (only used by disabled rules): {f.get('expression')}")
        else:
            print(f"Failed to delete filter {fid}: {del_resp.text}")

print("Done.")
