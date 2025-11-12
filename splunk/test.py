import requests
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


#zone_id=get_zone_id_from_domain("qp613CjQ07zaE28jWKmfdvUTT0wGjTvNl7jtwiBi","sgbgame.win")
#print(zone_id)
create_firewall_rule("sgbgame.win","qp613CjQ07zaE28jWKmfdvUTT0wGjTvNl7jtwiBi","AutoBlock-CustomRule1")
express=get_expression_from_rule_name("sgbgame.win","qp613CjQ07zaE28jWKmfdvUTT0wGjTvNl7jtwiBi")
print(express)