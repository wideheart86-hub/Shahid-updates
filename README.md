# SHAHID updates

Signed scam-intelligence updates for the SHAHID app (MH Team): reported scam websites, phrases and phone numbers.

- `pack.json` — the update (version, entries with their sources)
- `pack.json.sig` — ECDSA P-256 signature by MH Team's private key

The app accepts an update only if the signature verifies with the public key built into it, and entries can only
add warnings. To publish a change: edit `pack.json`, increase `version`, run
`python3 tools/sign_threatpack.py /secure/path/threatpack-signing-PRIVATE.pem` from the SHAHID repo (or sign
`pack.json` here the same way), and commit both files.

No user data is ever uploaded here.
