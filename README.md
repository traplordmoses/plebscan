# PlebScan

PlebScan is a Bitcoin metaprotocol asset aggregator written in Rust.  
It scans every child address derived from your P84 or P86 extended public key (xpub) and outputs a results.json file of your Ordinals and Runes holding accross up to 200 addresses, all in one place.

---

## What’s in this repository
This GitHub repo contains:

- **Rust backend** (`src/main.rs`) – derives child addresses from an xpub, queries the Hiro Ordinals API, and compiles results.

---

## What’s not here
Not included here (but used in development):

- **HTML templates & static assets** – Flask front-end UI files
- **`app.py`** – Flask server that powers the web interface
- **.env** - API keys

---

## Next up
- **Charts** — floor price history for each Ordinal
- **Runes bulk sell** — fire off multiple listings via the Magic Eden API
- (maybe) other meta-protocols as they blow up

---

## How to run
1. Clone it.
2. Build with Cargo.
3. Point it at your xpub + API key.
4. Get back `results.json` with everything you hold.

---

## License
TBD – project was co-built with AI; still deciding the terms.
