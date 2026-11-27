#!/usr/bin/env python3
"""Daily: collect live scam/phishing websites from open security feeds into feeds.json.

Keeps (1) every domain that impersonates a GCC brand or government service and (2) the freshest worldwide
phishing domains, up to MAX_TOTAL. SHAHID blocks whole domains, so shared hosting platforms and the
world's most popular websites (Tranco top 10k) are never included. Never fails the publish: on error the
previous feeds.json stays.
"""
import io, json, os, re, sys, urllib.request, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_TOTAL = 3000
UA = {"User-Agent": "Mozilla/5.0 (compatible; SHAHID-feeds/1.0)"}
FEEDS = [
    ("OpenPhish", "https://openphish.com/feed.txt"),
    ("URLhaus (abuse.ch)", "https://urlhaus.abuse.ch/downloads/text_online/"),
    ("Phishing.Database", "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"),
]
GCC = re.compile(r"rta|salik|nol|emiratespost|empost|aramex|dubai|abudhabi|sharjah|ajman|uae|emirates|etisalat|eand|\bdu\b|adcb|enbd|"
                 r"emiratesnbd|mashreq|fab|bankfab|adib|dib|rakbank|cbd|icp|uaepass|tamm|adpolice|moi|mohre|amer|tasheel|ejari|"
                 r"absher|stc|saudi|ksa|riyad|alrajhi|snb|sadad|tabby|tamara|qatar|ooredoo|qnb|kuwait|knet|zain|oman|bahrain|benefit|"
                 r"batelco|careem|noon|talabat|amazon\.ae|dhl|fedex|smsa|qpost|naqel|gcc|khaleej", re.I)
SHARED = {"google.com", "googleusercontent.com", "googleapis.com", "firebaseapp.com", "web.app", "appspot.com", "github.io",
          "githubusercontent.com", "github.com", "gitlab.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "r2.dev",
          "weebly.com", "wixsite.com", "wix.com", "blogspot.com", "wordpress.com", "square.site", "godaddysites.com", "webflow.io",
          "glitch.me", "herokuapp.com", "azurewebsites.net", "windows.net", "amazonaws.com", "cloudfront.net", "sharepoint.com",
          "onedrive.com", "live.com", "dropbox.com", "box.com", "bit.ly", "t.me", "wa.me", "ipfs.io", "000webhostapp.com",
          "ngrok.io", "ngrok-free.app", "duckdns.org", "replit.app", "repl.co", "surge.sh", "mybluehost.me", "framer.app",
          "canva.site", "notion.site", "jimdosite.com", "site123.me", "strikingly.com", "yolasite.com", "webnode.page",
          "carrd.co", "linktr.ee", "forms.gle", "typeform.com", "jotform.com", "telegra.ph", "medium.com", "tiny.cc", "tinyurl.com",
          "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "qrco.de", "s3.amazonaws.com", "cloudflare-ipfs.com", "translate.goog"}
SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "sch", "mil"}
OFFICIAL = {"rta.ae", "salik.ae", "emiratespost.ae", "dubaipolice.gov.ae", "u.ae", "adpolice.gov.ae", "moi.gov.ae", "tdra.gov.ae"}

def get(url, limit=60_000_000):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read(limit)

def registrable(host):
    host = host.lower().strip(".").removeprefix("www.")
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", host) or re.fullmatch(r"[0-9.]+", host): return None
    p = host.split(".")
    if len(p) >= 3 and p[-2] in SECOND_LEVEL and len(p[-1]) == 2: return ".".join(p[-3:])
    return ".".join(p[-2:])

def host_of(line):
    line = line.strip()
    if not line or line.startswith("#"): return None
    line = re.sub(r"^[a-z]+://", "", line, flags=re.I)
    return line.split("/")[0].split(":")[0]

def main():
    try:
        z = zipfile.ZipFile(io.BytesIO(get("https://tranco-list.eu/top-1m.csv.zip")))
        top = {l.split(",")[1].strip() for l in z.read(z.namelist()[0]).decode().splitlines()[:10000]}
    except Exception as e:
        print("Popular-sites list unavailable, keeping previous feeds.json:", e); return
    gcc, world, seen = [], [], set()
    for name, url in FEEDS:
        try: lines = get(url).decode("utf-8", "ignore").splitlines()
        except Exception as e: print("feed failed:", name, e, file=sys.stderr); continue
        n = 0
        for line in lines:
            h = host_of(line)
            if not h: continue
            d = registrable(h)
            if not d or d in seen or d in top or d in SHARED or d in OFFICIAL or any(d.endswith("." + o) for o in OFFICIAL): continue
            seen.add(d); n += 1
            entry = {"domain": d, "source": name + (": impersonates a GCC brand" if GCC.search(h) else "")}
            (gcc if GCC.search(h) else world).append(entry)
        print(f"{name}: {n} new domains")
    out = (gcc + world)[:MAX_TOTAL]
    if len(out) < 50:
        print("Too few domains; keeping the previous feeds.json"); return
    json.dump(out, open(os.path.join(ROOT, "feeds.json"), "w"), indent=0)
    print(f"feeds.json: {len(gcc)} GCC-related + {len(out) - min(len(gcc), MAX_TOTAL)} worldwide = {len(out)}")

if __name__ == "__main__":
    main()
