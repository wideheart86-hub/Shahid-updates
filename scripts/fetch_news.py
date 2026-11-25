#!/usr/bin/env python3
"""Collects the 5 most recent scam/fraud news stories about the UAE and GCC into news.json.

Only stories from the trusted news sites below are kept, so a fake "news" link can't get in.
Runs daily in GitHub Actions. Never fails the publish: on any error the previous news.json stays.
"""
import email.utils, html, json, os, re, sys, urllib.parse, urllib.request
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRUSTED = {"gulfnews.com", "khaleejtimes.com", "thenationalnews.com", "wam.ae", "emaratalyoum.com", "alkhaleej.ae",
           "albayan.ae", "alittihad.ae", "gulftoday.ae", "arabianbusiness.com", "zawya.com", "dubaipolice.gov.ae",
           "adpolice.gov.ae", "moi.gov.ae", "u.ae", "arabnews.com", "saudigazette.com.sa", "timesofoman.com",
           "gulf-times.com", "kuwaittimes.com", "gdnonline.com", "omanobserver.om", "aawsat.com", "alroeya.com",
           "24.ae", "erem.news", "alain.com", "skynewsarabia.com", "cnnarabic.com", "bbc.com", "reuters.com"}
TOPIC = re.compile(r"scam|fraud|phishing|swindl|con artist|impersonat|احتيال|نصب|محتال|تصيد|اختراق", re.I)
QUERIES = [("en", "scam UAE"), ("en", "fraud warning UAE police"), ("ar", "احتيال الإمارات"), ("ar", "تحذير شرطة احتيال")]
UA = {"User-Agent": "Mozilla/5.0 (compatible; SHAHID-news/1.0)"}
NS = {"media": "http://search.yahoo.com/mrss/", "News": "https://www.bing.com/news/search?q=&format=rss"}

def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=20) as r:
        return r.read()

def registrable(host):
    host = (host or "").lower().removeprefix("www.")
    parts = host.split(".")
    for n in (3, 2):
        if len(parts) >= n and ".".join(parts[-n:]) in TRUSTED: return ".".join(parts[-n:])
    return None

def clean(t):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", t or ""))).strip()

def bing(lang, q):
    mkt = "ar-AE" if lang == "ar" else "en-AE"
    url = "https://www.bing.com/news/search?" + urllib.parse.urlencode({"q": q, "format": "rss", "mkt": mkt, "qft": "sortbydate=\"1\""})
    out = []
    for it in ET.fromstring(get(url)).iter("item"):
        link = it.findtext("link") or ""
        u = urllib.parse.urlparse(link)
        if "bing.com" in u.netloc:  # unwrap apiclick redirect
            link = urllib.parse.parse_qs(u.query).get("url", [link])[0]
        img = ""
        for child in it:
            if child.tag.endswith("Image") and child.text: img = child.text.strip()
        out.append({"title": clean(it.findtext("title")), "url": link, "image": img, "lang": lang,
                    "date": it.findtext("pubDate") or "", "summary": clean(it.findtext("description"))[:240]})
    return out

def main():
    items = []
    for lang, q in QUERIES:
        try: items += bing(lang, q)
        except Exception as e: print("feed failed:", q, e, file=sys.stderr)
    seen, good = set(), []
    for it in items:
        u = urllib.parse.urlparse(it["url"])
        src = registrable(u.hostname)
        if u.scheme != "https" or not src: continue
        if not TOPIC.search(it["title"] + " " + it["summary"]): continue
        key = re.sub(r"\W+", "", it["title"].lower())[:60]
        if key in seen: continue
        seen.add(key)
        try: ts = email.utils.parsedate_to_datetime(it["date"]).timestamp()
        except Exception: continue
        if not it["image"].startswith("https://"): it["image"] = ""
        it["source"] = src; it["ts"] = int(ts); it.pop("date")
        good.append(it)
    good.sort(key=lambda x: -x["ts"])
    good = good[:5]
    for g in good:  # take the story's own picture (og:image) from the news site when the feed has none
        if g["image"]: continue
        try:
            page = get(g["url"])[:300000].decode("utf-8", "ignore")
            m = re.search(r'<meta[^>]+(?:property|name)=["\'](?:og:image|twitter:image)["\'][^>]+content=["\']([^"\']+)', page) \
                or re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\'](?:og:image|twitter:image)', page)
            if m and html.unescape(m.group(1)).startswith("https://"): g["image"] = html.unescape(m.group(1))
        except Exception as e:
            print("no picture for", g["url"], e, file=sys.stderr)
    if len(good) < 2:
        print("Not enough trusted stories found; keeping the previous news.json"); return
    path = os.path.join(ROOT, "news.json")
    old = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else []
    if [(o.get("url"), o.get("image")) for o in old] == [(g["url"], g["image"]) for g in good]:
        print("News unchanged"); return
    json.dump(good, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("News updated:", *[g["source"] + ": " + g["title"] for g in good], sep="\n  ")

if __name__ == "__main__":
    main()
