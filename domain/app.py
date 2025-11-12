from flask import Flask, render_template, request, redirect, url_for, flash
import os
import redis

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change_this_for_prod")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)

DOMAINS_SET = "domains:set"  # Redis set to store all domain names


def domain_key(domain, field=None):
    """Return Redis key like /<domain>/field"""
    if field:
        return f"/{domain}/{field}"
    return f"/{domain}/"


def append_ips(domain, field, new_ips):
    """Append new IPs to existing Redis value, avoid duplicates"""
    key = domain_key(domain, field)
    existing = r.get(key)
    if existing:
        existing_set = {ip.strip() for ip in existing.split(",") if ip.strip()}
    else:
        existing_set = set()

    new_set = {ip.strip() for ip in new_ips.split(",") if ip.strip()}
    merged = sorted(existing_set.union(new_set))
    r.set(key, ",".join(merged))


@app.route("/")
def index():
    domains = sorted(r.smembers(DOMAINS_SET) or [])
    items = []
    for d in domains:
        allow = r.get(domain_key(d, "allow")) or ""
        deny = r.get(domain_key(d, "deny")) or ""
        note = r.get(domain_key(d, "note")) or ""
        items.append({
            "domain": d,
            "allow_ip": allow,
            "deny_ip": deny,
            "note": note
        })
    return render_template("index.html", items=items)


@app.route("/add", methods=["POST"])
def add_domain():
    domain = request.form.get("domain", "").strip()
    allow_ip = request.form.get("allow_ip", "").strip()
    deny_ip = request.form.get("deny_ip", "").strip()
    note = request.form.get("note", "").strip()

    if not domain:
        flash("Domain cannot be empty", "error")
        return redirect(url_for("index"))

    # Append IPs instead of overwriting
    if allow_ip:
        append_ips(domain, "allow", allow_ip)
    if deny_ip:
        append_ips(domain, "deny", deny_ip)
    if note:
        r.set(domain_key(domain, "note"), note)

    # Track domain name
    r.sadd(DOMAINS_SET, domain)
    flash(f"Domain {domain} added/updated successfully", "success")
    return redirect(url_for("index"))


@app.route("/domain/<domain>")
def show_domain(domain):
    if not r.sismember(DOMAINS_SET, domain):
        flash("Domain not found", "error")
        return redirect(url_for("index"))

    data = {
        "allow_ip": r.get(domain_key(domain, "allow")) or "",
        "deny_ip": r.get(domain_key(domain, "deny")) or "",
        "note": r.get(domain_key(domain, "note")) or "",
    }
    return render_template("domain.html", domain=domain, data=data)


@app.route("/update/<domain>", methods=["POST"])
def update_domain(domain):
    if not r.sismember(DOMAINS_SET, domain):
        flash("Domain not found", "error")
        return redirect(url_for("index"))

    allow_ip = request.form.get("allow_ip", "").strip()
    deny_ip = request.form.get("deny_ip", "").strip()
    note = request.form.get("note", "").strip()

    # Replace note (single value)
    r.set(domain_key(domain, "note"), note)

    # Append IPs (merge mode)
    if allow_ip:
        append_ips(domain, "allow", allow_ip)
    if deny_ip:
        append_ips(domain, "deny", deny_ip)

    flash(f"{domain} updated successfully", "success")
    return redirect(url_for("show_domain", domain=domain))


@app.route("/delete/<domain>", methods=["POST"])
def delete_domain(domain):
    if not r.sismember(DOMAINS_SET, domain):
        flash("Domain not found", "error")
        return redirect(url_for("index"))

    # Delete all related keys
    r.delete(domain_key(domain, "allow"))
    r.delete(domain_key(domain, "deny"))
    r.delete(domain_key(domain, "note"))
    r.srem(DOMAINS_SET, domain)

    flash(f"{domain} deleted successfully", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
