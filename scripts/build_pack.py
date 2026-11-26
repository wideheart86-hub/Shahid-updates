#!/usr/bin/env python3
"""Builds pack.json from numbers.txt / websites.txt / phrases.txt and signs it.

The private key comes from the SHAHID_SIGNING_KEY environment variable (PEM text), provided by the
GitHub Actions secret of the same name. Never commit the key. Exits non-zero on invalid lines so a bad
edit is never published.
"""
import base64, json, os, re, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OFFICIAL = {"rta.ae", "salik.ae", "emiratespost.ae", "dubaipolice.gov.ae", "u.ae", "adpolice.gov.ae", "moi.gov.ae", "tdra.gov.ae"}

def read(name):
    out, errors = [], []
    path = os.path.join(ROOT, name)
    if not os.path.exists(path): return out, errors
    for i, raw in enumerate(open(path, encoding="utf-8"), 1):
        line = raw.strip()
        if not line or line.startswith("#"): continue
        value, _, source = line.partition("|")
        value, source = value.strip(), source.strip() or "MH Team"
        if len(value) > 200 or len(source) > 300: errors.append(f"{name}:{i}: line too long"); continue
        out.append((i, value, source))
    return out, errors

def main():
    errors = []
    nums, e = read("numbers.txt"); errors += e
    sites, e = read("websites.txt"); errors += e
    phrases, e = read("phrases.txt"); errors += e
    blocked_numbers, blocked_domains, phrase_list = [], [], []
    for i, v, s in nums:
        d = re.sub(r"[\s\-()]", "", v)
        if not re.fullmatch(r"\+?\d{6,15}", d): errors.append(f"numbers.txt:{i}: not a phone number: {v}"); continue
        blocked_numbers.append({"number": d, "source": s})
    for i, v, s in sites:
        d = re.sub(r"^https?://", "", v.lower()).split("/")[0].strip(".")
        if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d): errors.append(f"websites.txt:{i}: not a website name: {v}"); continue
        if d in OFFICIAL or any(d.endswith("." + o) for o in OFFICIAL): errors.append(f"websites.txt:{i}: official domain cannot be blocked: {d}"); continue
        blocked_domains.append({"domain": d, "source": s})
    for i, v, s in phrases:
        if len(v) < 4: errors.append(f"phrases.txt:{i}: phrase too short"); continue
        phrase_list.append({"text": v, "source": s})
    VAULT_IDS = {"fines", "delivery", "bank", "gov", "job", "invest", "family", "prize", "rent", "games", "drugs",
                 "links", "otp", "spoof", "remote", "qr", "social"}
    top_rows, e = read("top.txt"); errors += e
    top = []
    for i, v, s in top_rows:
        if v not in VAULT_IDS: errors.append(f"top.txt:{i}: unknown scam id: {v}"); continue
        top.append({"id": v, "source": s})
    news = []
    news_path = os.path.join(ROOT, "news.json")
    if os.path.exists(news_path):
        for n in json.load(open(news_path, encoding="utf-8"))[:5]:
            if str(n.get("url", "")).startswith("https://"):
                news.append({k: n.get(k, "") for k in ("title", "url", "image", "source", "ts", "lang", "summary")})
    app_rows, e = read("apps.txt"); errors += e
    bad_apps = []
    for i, v, s in app_rows:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+", v): errors.append(f"apps.txt:{i}: not an Android package name: {v}"); continue
        if v.startswith(("com.android.", "com.google.android.", "ae.shahid.")): errors.append(f"apps.txt:{i}: system or SHAHID app cannot be listed: {v}"); continue
        bad_apps.append({"package": v, "source": s})
    vault = []
    vpath = os.path.join(ROOT, "vault.json")
    if os.path.exists(vpath):
        try:
            for it in json.load(open(vpath, encoding="utf-8"))["items"]:
                if it.get("id") and it.get("cat") in ("type", "method") and all(isinstance(it.get(l), dict) and it[l].get("t") for l in ("en", "ar", "ur")):
                    vault.append(it)
                else: errors.append(f"vault.json: item {it.get('id')} needs id, cat (type/method) and en/ar/ur texts")
            if re.search("[\u064B\u064C\u064D]", json.dumps(vault, ensure_ascii=False)): errors.append("vault.json: Arabic text must not contain tanween")
        except Exception as ex: errors.append(f"vault.json: {ex}")
    app = None
    apk = os.path.join(ROOT, "app", "shahid.apk")
    if os.path.exists(apk):
        import hashlib
        v = json.load(open(os.path.join(ROOT, "app", "version.json"), encoding="utf-8"))
        app = {"versionCode": int(v["versionCode"]), "versionName": v["versionName"],
               "url": "https://raw.githubusercontent.com/wideheart86-hub/Shahid-updates/main/app/shahid.apk",
               "sha256": hashlib.sha256(open(apk, "rb").read()).hexdigest(),
               **{k: v.get(k, "") for k in ("notes_en", "notes_ar", "notes_ur")}}
    if errors:
        print("\n".join(errors)); sys.exit(1)

    pack_path = os.path.join(ROOT, "pack.json")
    old = json.load(open(pack_path, encoding="utf-8")) if os.path.exists(pack_path) else {"version": 0}
    body = {"blocked_domains": blocked_domains, "phrases": phrase_list, "blocked_numbers": blocked_numbers, "top": top, "news": news, "bad_apps": bad_apps, "vault": vault, "app": app}
    same = all(old.get(k) == v for k, v in body.items())
    if same and os.path.exists(pack_path + ".sig"):
        print("No changes; version stays", old.get("version")); return
    import datetime
    pack = {"version": int(old.get("version", 0)) + 1, "updated": datetime.date.today().isoformat(),
            "note": "SHAHID threat pack (MH Team). Entries can only ADD warnings. Built automatically from numbers.txt, websites.txt and phrases.txt.",
            **body}
    data = json.dumps(pack, ensure_ascii=False, indent=2).encode("utf-8")
    key_pem = os.environ.get("SHAHID_SIGNING_KEY", "").strip()
    if not key_pem:
        print("SHAHID_SIGNING_KEY secret is missing — add it in GitHub: Settings → Secrets and variables → Actions."); sys.exit(1)
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
    open(pack_path, "wb").write(data)
    open(pack_path + ".sig", "w").write(base64.b64encode(sig).decode() + "\n")
    print(f"Published version {pack['version']}: {len(blocked_numbers)} numbers, {len(blocked_domains)} websites, {len(phrase_list)} phrases, {len(top)} top scams, {len(news)} news, {len(bad_apps)} harmful apps, {len(vault)} vault items, app {app and app['versionName']}")

if __name__ == "__main__":
    main()
