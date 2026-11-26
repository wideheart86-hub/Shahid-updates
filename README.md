# SHAHID updates

Signed scam-intelligence updates for the SHAHID app (MH Team): reported scam websites, phrases and phone numbers.

- `pack.json` — the update (version, entries with their sources)
- `pack.json.sig` — ECDSA P-256 signature by MH Team's private key

The app accepts an update only if the signature verifies with the public key built into it, and entries can only
add warnings.

## How to add scam numbers, websites or phrases
1. Open `numbers.txt` (or `websites.txt` / `phrases.txt`) on GitHub and tap the ✏️ pencil.
2. Add one line per item:  `number | source`  — e.g.  `+971 50 000 0000 | Dubai Police warning, Dec 2026`
3. Tap **Commit changes**. Within about a minute the "Publish signed SHAHID update" job builds `pack.json`,
   increases the version, signs it and publishes it. Phones pick it up the next day (or with "Check for updates now").

Do not edit `pack.json` or `pack.json.sig` by hand. If a line is invalid, the job fails and nothing is published;
the Actions tab shows which line to fix.

No user data is ever uploaded here.

## Top scams and news
- **top.txt** — the "most common now" list shown first in the app's Scam Vault (first 5 shown). Reorder any time.
- **news.json** — filled automatically every day at 08:17 UAE time with the 5 latest scam news stories from trusted
  UAE/GCC news sites only (see `scripts/fetch_news.py`). To remove a story, delete it from news.json and commit.

## Harmful apps, scam library and app updates
- **apps.txt** — Android package names of games/apps confirmed harmful (endless pop-ups, hiding, installing other apps).
  The phone check-up flags them immediately.
- **vault.json** — the Scam Vault's scam types and methods (Arabic, English, Urdu). Edit a text or add an item
  (same `id` replaces the built-in one) and it reaches every phone with the next daily update. No tanween in Arabic.
- **app/shahid.apk + app/version.json** — publishing a new SHAHID version. The signed update carries its SHA-256,
  and the app installs it only if the file matches and is signed with the same release key.
