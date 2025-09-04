import os
import json
import time
import requests
import concurrent.futures
import subprocess
from dotenv import load_dotenv
from urllib.parse import quote
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    jsonify, send_from_directory
)



# Load env
load_dotenv()

# -------- caches --------
_floor_cache: dict[str, tuple[float, float]] = {}
_btc_usd_cache: tuple[float, float] = (0, 0.0)
_dashboard_cache: dict[str, tuple[float, str]] = {}
_rune_cache: dict[str, tuple[float, dict]] = {}

# --- Magic Eden throttle ---
_ME_MIN_INTERVAL = float(os.getenv("ME_MIN_INTERVAL", "0.35"))  # seconds between ME calls

# -------- BRC-20 (Xverse / SecretKeyLabs) --------
XV_API_BASE = os.getenv("XV_API_BASE", "https://api.secretkeylabs.io/v1").rstrip("/")
XV_KEY = os.getenv("XVERSE_API_KEY", "").strip()  # put in .env
XV_HEADERS = {"x-api-key": XV_KEY, "Accept": "application/json", "User-Agent": "plebscan-dashboard/1.0"}

_brc20_cache: dict[str, tuple[float, list[dict]]] = {}
_brc20_meta_cache: dict[str, tuple[float, dict]] = {}

# -------- Flask --------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY must be set in .env")

# -------- Magic Eden --------
ME_API_BASE = os.getenv("ME_API_BASE", "https://api-mainnet.magiceden.dev/v2/ord/btc").rstrip("/")
ME_KEY = os.getenv("ME_API_KEY", "").strip()
if not ME_KEY:
    raise RuntimeError("ME_API_KEY must be set in .env")

HEADERS = {
    "Authorization": f"Bearer {ME_KEY}",
    "X-API-KEY": ME_KEY,
    "Accept": "application/json",
    "User-Agent": "plebscan-dashboard/1.0",
}

# -------- Scanner binary (used to discover wallets & inscription_ids) --------
PLEBSCAN_BIN = os.getenv("PLEBSCAN_BIN", "/app/bin/pleb_scan")
if not os.path.isfile(PLEBSCAN_BIN):
    raise RuntimeError(
        f"PLEBSCAN_BIN not found at {PLEBSCAN_BIN}. "
        f"If using our Dockerfile it should be /app/bin/pleb_scan, "
        f"or set PLEBSCAN_BIN in the environment."
    )

# -------- Magic Eden Client --------
class MagicEdenClient:
    def __init__(self, base_url: str, api_key: str, min_interval: float = 0.35):
        self.base_url = base_url.rstrip('/')
        self.headers = {"Authorization": f"Bearer {api_key}", "X-API-KEY": api_key, "Accept": "application/json", "User-Agent": "plebscan-dashboard/1.0"}
        self.min_interval = min_interval
        self.last_call_ts = 0.0

    def get(self, endpoint: str, params: dict = None, attempts: int = 2, deadline_s: float = 2.5) -> dict | None:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        start = time.time()
        delay = 0.3
        for _ in range(attempts):
            wait = self.min_interval - (time.time() - self.last_call_ts)
            if wait > 0: time.sleep(wait)
            self.last_call_ts = time.time()
            try:
                resp = requests.get(url, params=params, headers=self.headers, timeout=12)
                if resp.status_code == 429:
                    sleep_for = self._parse_retry_after(resp, delay)
                    if (time.time() - start) + sleep_for >= deadline_s: return None
                    time.sleep(sleep_for)
                    delay = min(delay * 1.6, 2.5)
                    continue
                if resp.status_code == 404: return None
                resp.raise_for_status()
                if "application/json" in (resp.headers.get("content-type") or "").lower():
                    return resp.json()
            except Exception:
                pass
        return None

    def _parse_retry_after(self, resp, fallback: float) -> float:
        ra = resp.headers.get("retry-after")
        reset = resp.headers.get("x-ratelimit-reset")
        try:
            if ra is not None:
                v = float(ra)
                wait = v / 1000.0 if v >= 1000 else v
            elif reset is not None:
                wait = float(reset)
            else:
                wait = fallback
        except Exception:
            wait = fallback
        return max(0.2, min(wait, 10.0))

me_client = MagicEdenClient(ME_API_BASE, ME_KEY, _ME_MIN_INTERVAL)

# -------- helpers --------
def extract_last_json(text: str) -> dict | None:
    last_brace = text.rfind("{")
    if last_brace == -1:
        return None
    candidate = text[last_brace:]
    for _ in range(10):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            candidate = candidate.rstrip()
            if not candidate:
                break
            candidate = candidate[:-1]
    return None

def load_results_json_fallback() -> list[dict]:
    """Try to load wallets from results.json next to app.py if session is empty."""
    p = os.path.join(os.path.dirname(__file__), "results.json")
    if os.path.isfile(p):
        try:
            with open(p, "r") as f:
                data = json.load(f)
                return data.get("wallets", [])
        except Exception:
            pass
    return []

def get_btc_usd_rate() -> float:
    global _btc_usd_cache
    now = time.time()
    ts, rate = _btc_usd_cache
    if now - ts < 60 and rate != 0.0:
        return rate
    try:
        resp = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": "bitcoin", "vs_currencies": "usd"},
            timeout=10,
        )
        resp.raise_for_status()
        rate = float(resp.json()["bitcoin"]["usd"])
        _btc_usd_cache = (now, rate)
        return rate
    except Exception:
        return rate or 0.0

def get_token_details(all_ids: list[str]) -> list[dict]:
    """Magic Eden /tokens?tokenIds=... (batched)."""
    if not all_ids:
        return []
    CHUNK_SIZE = 50
    results: list[dict] = []

    def fetch_chunk(chunk_ids: list[str]) -> list[dict]:
        params = {"tokenIds": ",".join(chunk_ids)}
        for _ in range(2):
            data = me_client.get("tokens", params=params)
            if data is None:
                time.sleep(1)
                continue
            if isinstance(data, dict) and "tokens" in data:
                return data["tokens"]
            if isinstance(data, list):
                return data
            app.logger.error("Unexpected /tokens response: %r", data)
            return []
        return []

    chunks = [all_ids[i:i + CHUNK_SIZE] for i in range(0, len(all_ids), CHUNK_SIZE)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(fetch_chunk, c) for c in chunks]
        for fut in concurrent.futures.as_completed(futures):
            results.extend(fut.result())
    return results

SATS_LIKE_KEYS = (
    "floorPrice","floorPriceInSats","floorInSats","priceInSats","unitPriceSats",
    "floorPriceSats","floor_sats","floorSats","lowestListingInSats","lowestListingPrice",
    "bestAsk","bestAskInSats","lowestAsk","minPrice","min","askSats","priceSats",
    "floorUnitPrice"  # NEW (lets the walker descend)
)

def extract_price(data: dict, keys: tuple[str, ...] = SATS_LIKE_KEYS, prefer_sats: bool = True, per_rune: bool = False) -> float:
    """
    Walk dict for first matching key's value. Convert to sats (if prefer_sats) or BTC.
    If per_rune, scale by 10**divisibility (for runes).
    Handles nested 'formatted'/'value', strings, ints/floats.
    """
    def parse_val(v: any) -> float | None:
        if isinstance(v, (int, float)): return float(v)
        if isinstance(v, str):
            num = ''.join(c for c in v.lower().replace(',', '') if c.isdigit() or c == '.')
            return float(num) if num else None
        return None

    stack = [data]
    div = extract_divisibility(data) if per_rune else 0
    while stack:
        cur = stack.pop()
        if not isinstance(cur, dict): continue
        for k, v in cur.items():
            if k.lower() in (key.lower() for key in keys):
                if isinstance(v, dict):  # e.g., floorUnitPrice {value, formatted}
                    formatted = v.get('formatted') or ''
                    if 'sat' in formatted.lower():
                        val = parse_val(formatted)
                        unit = 'sats'
                    else:
                        val = parse_val(v.get('value'))
                        unit = 'btc'
                else:
                    val = parse_val(v)
                    unit = 'sats' if 'sats' in k.lower() or (val is not None and val > 1e3) else 'btc'
                if val is not None:
                    sats = val if unit == 'sats' else val * 1e8
                    if per_rune: sats *= (10 ** div)
                    return sats if prefer_sats else sats / 1e8
            if isinstance(v, dict): stack.append(v)
            elif isinstance(v, list): stack.extend(d for d in v if isinstance(d, dict))
    return 0.0

def extract_divisibility(data: dict) -> int:
    try:
        return int(extract_price(data, keys=('divisibility',), prefer_sats=False))  # Reuse for int
    except Exception:
        return 0

def _extract_rune_symbol(data: dict) -> str:
    """
    Walk the dict to find the rune symbol (usually an emoji like 💥 or 🐕).
    """
    stack = [data]
    while stack:
        cur = stack.pop()
        if not isinstance(cur, dict): continue
        for k, v in cur.items():
            if k.lower() in ('symbol', 'runesymbol', 'etchedsymbol', 'unit') and isinstance(v, str) and len(v) <= 2 and not v.isalnum():
                return v
            if isinstance(v, dict): stack.append(v)
            elif isinstance(v, list): stack.extend(d for d in v if isinstance(d, dict))
    return ""

def get_floor_map(collection_symbols: set[str]) -> dict[str, float]:
    """
    Return {symbol: floor_btc} with caching + throttled multi-endpoint fetch.
    """
    now = time.time()
    floor: dict[str, float] = {}
    to_fetch: list[str] = []

    for sym in collection_symbols:
        ts, cp = _floor_cache.get(sym, (0, None))
        if cp is not None and now - ts < 60:
            floor[sym] = cp
        else:
            to_fetch.append(sym)

    if not to_fetch:
        return floor

    def fetch(sym: str) -> tuple[str, float]:
        price = _try_collection_stats(sym)
        return sym, price

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(fetch, s) for s in to_fetch]
        for fut in concurrent.futures.as_completed(futures):
            sym, price = fut.result()
            _floor_cache[sym] = (now, price)
            floor[sym] = price

    return floor

def _try_collection_stats(symbol: str) -> float:
    """
    Ask ME for collection stats using a few known routes, return floor in BTC.
    """
    candidates = [
        f"stat?collectionSymbol={quote(symbol)}",
        f"collections/{quote(symbol)}/stats",
        f"collection_stats?collectionSymbol={quote(symbol)}",
    ]
    for endpoint in candidates:
        data = me_client.get(endpoint)
        if data:
            price = extract_price(data, prefer_sats=False)
            if price > 0:
                return round(price, 8)
    return 0.0

def _get_collection_symbol(t: dict) -> str | None:
    """
    Try the common places Magic Eden returns the collection symbol.
    """
    if not isinstance(t, dict):
        return None

    # direct field
    sym = t.get("collectionSymbol")
    if sym:
        return str(sym)

    # nested shapes sometimes used by ME
    coll = t.get("collection") or {}
    for k in ("symbol", "slug", "collectionSymbol", "collection_slug"):
        v = coll.get(k)
        if v:
            return str(v)

    # occasionally under meta fields
    meta = t.get("meta") or {}
    for k in ("collectionSymbol", "symbol", "slug"):
        v = meta.get(k)
        if v:
            return str(v)

    return None

def _ipfs_to_http(u: str) -> str:
    if not isinstance(u, str):
        return ""
    u = u.strip()
    if u.startswith("ipfs://"):
        return "https://ipfs.io/ipfs/" + u[len("ipfs://"):]
    return u

def _pick_img_url(token: dict) -> str:
    """Pick a decent image URL from common ME shapes (with IPFS fallback)."""
    if not isinstance(token, dict):
        token = {}

    # flat
    for k in ("contentPreviewURI", "contentURI"):
        u = token.get(k)
        if u:
            return _ipfs_to_http(u)

    # nested content
    content = token.get("content") or {}
    for k in ("preview", "uri"):
        u = content.get(k)
        if u:
            return _ipfs_to_http(u)

    # nested meta
    meta = token.get("meta") or {}
    for k in ("image", "image_url", "imageURI"):
        u = meta.get(k)
        if u:
            return _ipfs_to_http(u)

    # other fallbacks
    for k in ("tokenURI", "imageURI", "image"):
        u = token.get(k)
        if u:
            return _ipfs_to_http(u)

    return ""

def _rune_me_url(name: str | None = None, spaced_name: str | None = None, rune_id: str | None = None) -> str:
    """
    Magic Eden runes UI wants the spaced name with bullet separators, URL-encoded.
    Fallbacks: ticker name, then rune_id.
    """
    slug = spaced_name or name or rune_id or ""
    slug = quote(slug, safe=":")  # keep ':' in ids like '840000:3', encode bullets, etc.
    return f"https://magiceden.io/runes/{slug}"

def get_rune_info_map(runes: list[dict], deadline_s: float = 2.5) -> dict[str, dict]:
    """
    Pull rune market info from Magic Eden.

    Display: use floorUnitPrice.formatted exactly (e.g., "2.821396003389517 sats/🐕").
    Math:    if floorUnitPrice.value exists, treat it as BTC-per-UNIT -> compute per-RUNE.
             else try to parse formatted number & unit to get per-UNIT sats.
    """
    now = time.time()
    uniq: dict[str, dict] = {r['name']: r for r in runes if r.get('name')}
    out: dict[str, dict] = {}

    for name, r in uniq.items():
        ts, cached = _rune_cache.get(name, (0.0, None))
        if cached and (now - ts) < 60:
            out[name] = cached
            continue

        spaced = r.get('spaced_name') or name
        candidates = [quote(spaced, safe=":"), quote(name, safe=":")]

        payload = {
            "floor_sats": 0.0,          # per RUNE (sats) for math
            "floor_btc": 0.0,           # per RUNE (BTC) for math
            "floor_unit_sats": 0.0,     # per UNIT (sats) for reference
            "divisibility": 0,
            "symbol": "",
            "me_url": _rune_me_url(name, spaced, r.get('id')),
            "floor_display": "",         # EXACT ME string when present
            "raw": {},
        }

        for slug in candidates:
            data = me_client.get(f"runes/market/{slug}/info", deadline_s=deadline_s)
            if not data:
                continue

            div = extract_divisibility(data)
            fup = data.get("floorUnitPrice") or {}
            formatted = str(fup.get("formatted") or "").strip()
            symbol = _extract_rune_symbol(data) or ""

            # Always show ME's own formatted string if present.
            floor_disp = formatted

            # --- Math path (only what we need) ---
            per_unit_sats = 0.0

            # Preferred: numeric value is BTC-per-UNIT
            val = fup.get("value")
            if val is not None:
                try:
                    per_unit_sats = float(val) * 1e8
                except Exception:
                    per_unit_sats = 0.0

            # Fallback: parse formatted string if value missing
            if per_unit_sats <= 0.0 and formatted:
                low = formatted.lower().replace(",", "")
                num = _extract_first_float(formatted) or 0.0
                if num:
                    if "btc" in low:
                        per_unit_sats = num * 1e8
                    elif "sat" in low:
                        # assume this is per-UNIT sats (matches how ME renders "sats/🐕")
                        per_unit_sats = num

            # Derive per-RUNE from per-UNIT via divisibility
            per_rune_sats = per_unit_sats * (10 ** div) if div else per_unit_sats
            per_rune_btc = per_rune_sats / 1e8

            # If ME didn't give formatted, synthesize a simple fallback for UI
            if not floor_disp:
                if symbol:
                    floor_disp = f"{per_unit_sats:.8f} sats/{symbol}"
                else:
                    floor_disp = f"{per_unit_sats:.8f} sats"

            payload.update({
                "divisibility": div,
                "symbol": symbol,
                "floor_unit_sats": per_unit_sats,
                "floor_sats": per_rune_sats,
                "floor_btc": per_rune_btc,
                "floor_display": floor_disp,
                "raw": data,
            })

            break  # first usable slug

        _rune_cache[name] = (now, payload)
        out[name] = payload

    return out

from decimal import Decimal, getcontext
getcontext().prec = 50

def _hr_amount(int_str: str | int | float, decimals: int) -> str:
    try:
        q = Decimal(str(int_str)) / (Decimal(10) ** int(decimals))
        s = format(q, "f").rstrip("0").rstrip(".")
        return s if s else "0"
    except Exception:
        return str(int_str)

def _get_brc20_meta(ticker: str) -> dict:
    """Fetch decimals and build a unisat_url for a ticker (cached ~1h)."""
    now = time.time()
    ts, cached = _brc20_meta_cache.get(ticker.lower(), (0, None))
    if cached and now - ts < 3600:
        return cached
    if not XV_KEY:
        meta = {"ticker": ticker, "decimals": 18}  # safe fallback
    else:
        meta = {"ticker": ticker, "decimals": 18}
        try:
            r = requests.get(f"{XV_API_BASE}/brc20/ticker/{ticker}", headers=XV_HEADERS, timeout=12)
            if r.ok and r.headers.get("content-type","").lower().startswith("application/json"):
                j = r.json() or {}
                if isinstance(j, dict) and "decimals" in j:
                    meta["decimals"] = int(j.get("decimals") or 18)
        except Exception:
            pass
    meta["unisat_url"] = f"https://unisat.io/market/brc20?tick={ticker}"
    _brc20_meta_cache[ticker.lower()] = (now, meta)
    return meta

def fetch_brc20_balances(address: str) -> list[dict]:
    """Return [{'ticker','decimals','available','transferable','overall','available_hr',...,'unisat_url'}, ...]"""
    if not address:
        return []
    now = time.time()
    ts, cached = _brc20_cache.get(address, (0, None))
    if cached and now - ts < 60:
        return cached

    items = []
    if XV_KEY:
        try:
            url = f"{XV_API_BASE}/ordinals/address/{address}/brc20"
            r = requests.get(url, headers=XV_HEADERS, timeout=12)
            if r.ok and r.headers.get("content-type","").lower().startswith("application/json"):
                data = r.json() or {}
                items = data.get("items") or []
        except Exception:
            items = []
    # shape to your template
    out = []
    for it in items:
        ticker = str(it.get("ticker","")).lower()
        if not ticker:
            continue
        meta = _get_brc20_meta(ticker)
        dec  = int(meta.get("decimals", 18))
        avail = it.get("availableBalance") or it.get("available") or "0"
        transf = it.get("transferableBalance") or it.get("transferable") or "0"
        overall = it.get("overallBalance") or it.get("overall") or "0"
        out.append({
            "ticker": ticker,
            "decimals": dec,
            "available": str(avail),
            "transferable": str(transf),
            "overall": str(overall),
            "available_hr": _hr_amount(avail, dec),
            "transferable_hr": _hr_amount(transf, dec),
            "overall_hr": _hr_amount(overall, dec),
            "unisat_url": meta.get("unisat_url"),
        })
    _brc20_cache[address] = (now, out)
    return out


def _extract_first_float(s: str) -> float | None:
    if not isinstance(s, str):
        return None
    s = s.strip().lower().replace(",", "")
    num, dot = [], False
    for ch in s:
        if ch.isdigit():
            num.append(ch)
        elif ch == "." and not dot:
            num.append(ch); dot = True
        elif num:
            break
    try:
        return float("".join(num)) if num else None
    except Exception:
        return None

def _tok_id(t: dict) -> str | None:
    return t.get("id") or t.get("tokenId") or t.get("inscriptionId")

def _fetch_brc20_unisat(addr: str) -> list[dict]:
    """Fallback: UniSat Open API summary by address (no pricing; balances only)."""
    if not addr:
        return []
    base = os.getenv("UNISAT_BASE", "https://open-api.unisat.io").rstrip("/")
    url = f"{base}/v1/indexer/address/{addr}/brc20/summary"
    headers = {
        "Accept": "application/json",
        "User-Agent": "plebscan-dashboard/1.0",
    }
    key = os.getenv("UNISAT_API_KEY", "").strip()
    if key:
        headers["Authorization"] = f"Bearer {key}"

    try:
        r = requests.get(url, headers=headers, timeout=15)
        if not r.ok:
            app.logger.debug("UniSat %s -> HTTP %s: %s", addr, r.status_code, r.text[:200])
            return []
        j = r.json() or {}
        detail = ((j.get("data") or {}).get("detail")) or []
        out = []
        for it in detail:
            ticker = str(it.get("ticker") or "").lower()
            if not ticker:
                continue
            available = str(it.get("availableBalance") or "0")
            transferable = str(
                it.get("transferableBalance")
                or it.get("transferrable_balance")
                or it.get("transferable_balance")
                or "0"
            )
            overall = str(it.get("overallBalance") or "0")

            # decimals may or may not be present in this endpoint
            dec = it.get("decimal") or it.get("decimals") or it.get("divisibility")
            try:
                decimals = int(dec) if dec is not None else None
            except Exception:
                decimals = None

            if decimals is not None:
                available_hr = _hr_amount(available, decimals)
                transferable_hr = _hr_amount(transferable, decimals)
                overall_hr = _hr_amount(overall, decimals)
            else:
                available_hr = transferable_hr = overall_hr = None

            out.append({
                "ticker": ticker,
                "decimals": decimals,
                "available": available,
                "transferable": transferable,
                "overall": overall,
                "available_hr": available_hr,
                "transferable_hr": transferable_hr,
                "overall_hr": overall_hr,
                "unisat_url": f"https://unisat.io/market/brc20?tick={ticker}",
            })
        return out
    except Exception as e:
        app.logger.warning("UniSat fallback error for %s: %s", addr, e)
        return []


@app.route("/debug/rune_info")
def debug_rune_info():
    name = request.args.get("name", "").strip()      # e.g. EPICEPICEPICEPIC
    spaced = request.args.get("spaced", "").strip()  # e.g. EPIC•EPIC•EPIC•EPIC
    if not name and not spaced:
        return jsonify({"error": "pass ?name= or ?spaced="}), 400
    candidates = []
    if spaced: candidates.append(quote(spaced, safe=":"))
    if name:   candidates.append(quote(name,   safe=":"))
    results = []
    for slug in candidates:
        url = f"{ME_API_BASE}/runes/market/{slug}/info"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=12)
            ct = (resp.headers.get("content-type") or "").lower()
            out = {
                "url": url,
                "status": resp.status_code,
                "content_type": ct,
                "retry_after": resp.headers.get("retry-after"),
                "x_ratelimit_limit": resp.headers.get("x-ratelimit-limit"),
                "x_ratelimit_remaining": resp.headers.get("x-ratelimit-remaining"),
                "x_ratelimit_reset": resp.headers.get("x-ratelimit-reset"),
            }
            if "application/json" in ct:
                try: out["json"] = resp.json()
                except Exception: out["body"] = resp.text[:2000]
            else:
                out["body"] = resp.text[:2000]
            results.append(out)
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    return jsonify({"candidates_tried": candidates, "results": results})

@app.route("/dashboard/debug/rune_info")
def debug_rune_info_alias():
    # redirect to the real debug route so old/guessed URL works
    return redirect(url_for(
        "debug_rune_info",
        name=(request.args.get("name","") or "").strip(),
        spaced=(request.args.get("spaced","") or "").strip(),
    ), code=302)

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )

# ============ Routes ============

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        xpub = request.form.get("xpub", "").strip()
        purpose = request.form.get("purpose")
        max_addresses = request.form.get("max", "200").strip()
        network = request.form.get("network", "bitcoin").strip()
        chain = request.form.get("chain", "0").strip()

        if not xpub:
            flash("Please enter a valid XPUB or TPUB", "warning")
            return redirect(url_for("index"))
        if purpose not in ["p44", "p49", "p84", "p86"]:
            flash("Please select a valid derivation path", "warning")
            return redirect(url_for("index"))
        try:
            max_addresses = int(max_addresses)
            chain = int(chain)
            if max_addresses < 1 or chain not in [0, 1]:
                raise ValueError
        except ValueError:
            flash("Max addresses must be a positive integer and chain must be 0 or 1", "warning")
            return redirect(url_for("index"))
        if network not in ["bitcoin", "testnet"]:
            flash("Network must be 'bitcoin' or 'testnet'", "warning")
            return redirect(url_for("index"))

        # persist for /dashboard
        session["xpub"] = xpub
        session["purpose"] = purpose
        session["network"] = network
        session["chain"] = chain

        # Run scanner (CLI)
        cmd = [
            PLEBSCAN_BIN,
            "--purpose", purpose,
            "--xpub", xpub,
            "--max", str(max_addresses),
            "--miss-limit", "20",
            "--sleep-ms", "100",
            "--verbose",
            "--network", network,
            "--chain", str(chain),
            "--base-url", os.getenv("HIRO_BASE", "https://api.hiro.so"),
        ]
        hiro_key = os.getenv("HIRO_API_KEY")
        if hiro_key:
            cmd.extend(["--api-key", hiro_key])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
            raw_output = proc.stdout
            data = extract_last_json(raw_output) or json.load(open("results.json"))
            wallets = data.get("wallets", [])
            session["plebscan_wallets"] = wallets

            if not wallets:
                flash("No inscriptions found for that XPUB (or scan limit too low).", "info")

            return redirect(url_for("dashboard"))
        except subprocess.CalledProcessError as e:
            app.logger.error("Scanner failed: %s\nstdout:\n%s\nstderr:\n%s", e, e.stdout, e.stderr)
            flash(f"Scanner failed: {e.stderr or e}", "danger")
            return redirect(url_for("index"))
        except Exception as e:
            app.logger.exception("Unexpected error running scanner")
            flash(f"Unexpected error: {e}", "danger")
            return redirect(url_for("index"))

    return render_template("index.html")
  

def enrich_wallets(wallets, skip_runes, deadline):
    # Collect all unique inscription IDs from scanner output
    all_ids = list({
        iid
        for w in wallets
        for iid in (w.get("inscription_ids") or [])
        if iid
    })

    tokens = get_token_details(all_ids)
    token_map = { _tok_id(t): t for t in tokens if _tok_id(t) }

    coll_syms = { s for t in tokens for s in [_get_collection_symbol(t)] if s }
    floor_map = get_floor_map(coll_syms)
    btc_usd = get_btc_usd_rate()

    enriched = []
    total_btc = total_usd = 0.0

    # RUNES: gather unique names and fetch market info once
    runes_flat = [] if skip_runes else [r for w in wallets for r in (w.get("runes") or []) if r.get("name")]
    rune_info_map = {} if skip_runes else get_rune_info_map(runes_flat, deadline_s=deadline)

    # Helper to normalize BRC-20 shapes that the scanner may emit
    def _normalize_brc20(base):
        """Accept list or dict and normalize for the template."""
        if not base:
            return []
        if isinstance(base, dict):
            base = list(base.values())
        out = []
        if isinstance(base, list):
            for b in base:
                if not isinstance(b, dict):
                    continue
                b = dict(b)
                # display fallbacks
                b["available_hr"]    = b.get("available_hr")    or b.get("available")
                b["transferable_hr"] = b.get("transferable_hr") or b.get("transferable")
                b["overall_hr"]      = b.get("overall_hr")      or b.get("overall")
                # market link
                if b.get("ticker") and not b.get("unisat_url"):
                    b["unisat_url"] = f"https://unisat.io/market/brc20?tick={b['ticker']}"
                out.append(b)
        return out

    for w in wallets:
        tok_list = []
        wallet_btc = wallet_usd = 0.0

        # ----- inscriptions -----
        for iid in (w.get("inscription_ids") or []):
            t = token_map.get(iid)
            if not t:
                continue

            sym = _get_collection_symbol(t)
            fp_btc = floor_map.get(sym, 0.0)
            fp_usd = round(fp_btc * btc_usd, 2)
            img_url = _pick_img_url(t)

            item = dict(t)
            item.update({
                "owner_address": w.get("pubkey"),
                "value": None,
                "img_url": img_url,   # template can ignore this; harmless
                "floorPrice": fp_btc,
                "floorUSD": fp_usd,
            })

            wallet_btc += fp_btc
            wallet_usd += fp_usd
            tok_list.append(item)

        tok_list.sort(key=lambda x: x["floorPrice"], reverse=True)

        # ----- BRC-20 (scanner → Xverse → UniSat) -----
        base = (
            w.get("brc20") or
            w.get("brc20_tokens") or
            w.get("brc20s") or
            w.get("brc20_balances") or
            []
        )
        brc = _normalize_brc20(base)

        if not brc:
            addr = w.get("pubkey") or ""
            if addr:
                # 1) try Xverse/SecretKeyLabs (requires XVERSE_API_KEY)
                try:
                    xv = _normalize_brc20(fetch_brc20_balances(addr))
                except Exception as e:
                    app.logger.debug("BRC-20 XV fallback failed for %s: %s", addr, e)
                    xv = []
                if xv:
                    brc = xv
                    app.logger.debug("BRC-20 (xverse) %s -> %d tickers", addr, len(brc))
                else:
                    # 2) final fallback: UniSat open API
                    us = _normalize_brc20(_fetch_brc20_unisat(addr))
                    if us:
                        brc = us
                        app.logger.debug("BRC-20 (unisat) %s -> %d tickers", addr, len(brc))

        # prefer actual list length; otherwise fall back to any provided count
        brc_count = len(brc) if brc else int(w.get("brc20_count") or 0)
        app.logger.debug("BRC-20 (resolved) %s -> %d tickers", w.get("pubkey"), brc_count)


        # ----- RUNES enrichment -----
        runes_enriched = []
        runes_sum_btc = runes_sum_usd = 0.0

        for r in (w.get("runes") or []):
            name = r.get("name") or ""
            spaced = r.get("spaced_name") or name

            bal_s = str(r.get("balance", "0"))
            try:
                balance = float(bal_s)
            except Exception:
                balance = 0.0

            info = rune_info_map.get(name, {}) or {}
            floor_sats = float(info.get("floor_sats", 0.0))   # per RUNE (ref)
            floor_btc  = float(info.get("floor_btc", 0.0))    # per RUNE (ref)
            div        = int(info.get("divisibility", 0) or 0)

            # prefer ME's sats/<symbol> per-UNIT for math
            floor_unit_sats = float(info.get("floor_unit_sats", 0.0))
            if floor_unit_sats <= 0.0:
                fd = (info.get("floor_display") or "").lower().replace(",", "")
                num = _extract_first_float(fd) or 0.0
                if num:
                    floor_unit_sats = num * 1e8 if "btc" in fd else num

            raw_fup = ((info.get("raw") or {}).get("floorUnitPrice") or {})
            fd_str  = str(raw_fup.get("formatted") or info.get("floor_display") or "").strip()
            fd_low  = fd_str.lower().replace(",", "")
            num     = _extract_first_float(fd_str) or 0.0
            sats_per_unit = num * 1e8 if (num > 0.0 and "btc" in fd_low) else (num if num > 0.0 else float(info.get("floor_unit_sats", 0.0)))

            bag_sats = int(round(sats_per_unit * balance))
            bag_btc  = round(bag_sats / 1e8, 10)
            bag_usd  = round(bag_btc * btc_usd, 2)

            runes_enriched.append({
                "name": name,
                "spaced_name": spaced,
                "id": r.get("id"),
                "balance": bal_s,
                "floor_unit_sats": floor_unit_sats,
                "divisibility": div,
                "floor_sats": floor_sats,
                "floor_btc": floor_btc,
                "floor_usd": round(floor_btc * btc_usd, 2),
                "floor_display": info.get("floor_display", f"{floor_unit_sats:.8f} sats/{info.get('symbol','')}"),
                "bag_sats": bag_sats,
                "bag_btc": bag_btc,
                "bag_usd": bag_usd,
                "me_url": info.get("me_url") or _rune_me_url(name, r.get("spaced_name"), r.get("id")),
                "symbol": info.get("symbol", ""),
            })
            runes_sum_btc += bag_btc
            runes_sum_usd += bag_usd

        runes_enriched.sort(key=lambda x: x["bag_btc"], reverse=True)

        summary = dict(w)
        summary.update({
            "tokens": tok_list,
            "inscription_count": len(tok_list),
            "floor_sum_btc": round(wallet_btc, 6),
            "floor_sum_usd": round(wallet_usd, 2),

            "runes": runes_enriched,
            "runes_count": len(runes_enriched),
            "runes_sum_btc": round(runes_sum_btc, 6),
            "runes_sum_usd": round(runes_sum_usd, 2),

            "brc20": brc,
            "brc20_count": brc_count,
        })

        total_btc += wallet_btc
        total_usd += wallet_usd
        enriched.append(summary)

    enriched.sort(key=lambda x: x["floor_sum_btc"], reverse=True)
    return enriched, total_btc, total_usd


@app.route("/dashboard")
def dashboard():
    xpub = session.get("xpub")
    if not xpub:
        flash("No XPUB found. Please scan an XPUB first.", "warning")
        return redirect(url_for("index"))
    
    skip_runes = request.args.get("no_runes") == "1"
    slow_runes = request.args.get("slow_runes") == "1"
    deadline = 6.0 if slow_runes else 2.5

    now = time.time()
    cached_ts, cached_html = _dashboard_cache.get(xpub, (0, None))
    if cached_html and now - cached_ts < 30:
        return cached_html

    wallets = session.get("plebscan_wallets") or load_results_json_fallback()
    if not wallets:
        flash("No wallets in session. Run a scan on the home page (or ensure results.json exists).", "info")

    enriched, total_btc, total_usd = enrich_wallets(wallets, skip_runes, deadline)

    purpose_display = {
        "p44": "BIP-44 (Legacy, P2PKH)",
        "p49": "BIP-49 (Nested SegWit, P2SH-P2WPKH)",
        "p84": "BIP-84 (Native SegWit, P2WPKH)",
        "p86": "BIP-86 (Taproot, P2TR)",
    }.get(session.get("purpose", "p84"), "Unknown")

    html = render_template(
        "dashboard.html",
        wallets=enriched,
        total_inscriptions=sum(w["inscription_count"] for w in enriched),
        total_wallets=len(enriched),
        total_floor_btc=round(total_btc, 6),
        total_floor_usd=round(total_usd, 2),
        xpub=xpub,
        purpose=purpose_display,
    )
    _dashboard_cache[xpub] = (now, html)
    return html

@app.route("/dashboard_test")
def dashboard_test():
    test_path = os.path.join(os.path.dirname(__file__), "test_inscriptions.json")
    with open(test_path) as f:
        wallets = json.load(f)["wallets"]

    all_ids = list({iid for w in wallets for iid in w.get("inscription_ids", [])})
    tokens = get_token_details(all_ids)
    coll_syms = { s for t in tokens for s in [_get_collection_symbol(t)] if s }
    floor_map = get_floor_map(coll_syms)
    btc_usd = get_btc_usd_rate()
    total_floor_btc = total_floor_usd = 0.0

    for w in wallets:
        tok_list = []
        wallet_btc = wallet_usd = 0.0
        for iid in w.get("inscription_ids", []):
            t = next((x for x in tokens if _tok_id(x) == iid), None)
            if not t:
                continue
            sym = _get_collection_symbol(t)
            fp_btc = floor_map.get(sym, 0.0)
            t["floorPrice"] = fp_btc
            t["floorUSD"] = round(fp_btc * btc_usd, 2)
            t["img_url"] = _pick_img_url(t)
            wallet_btc += fp_btc
            wallet_usd += t["floorUSD"]
            tok_list.append(t)
        tok_list.sort(key=lambda t: t["floorPrice"], reverse=True)
        w.update({
            "tokens": tok_list,
            "inscription_count": len(tok_list),
            "floor_sum_btc": round(wallet_btc, 6),
            "floor_sum_usd": round(wallet_usd, 2),
        })
        total_floor_btc += wallet_btc
        total_floor_usd += wallet_usd

    wallets.sort(key=lambda w: w["floor_sum_btc"], reverse=True)
    return render_template(
        "dashboard.html",
        wallets=wallets,
        total_inscriptions=sum(w["inscription_count"] for w in wallets),
        total_wallets=len(wallets),
        total_floor_btc=round(total_floor_btc, 6),
        total_floor_usd=round(total_floor_usd, 2),
    )

@app.route("/debug/wallets_raw")
def debug_wallets_raw():
    wallets = session.get("plebscan_wallets") or load_results_json_fallback()
    return jsonify({"wallets": wallets})


@app.route("/debug/brc20")
def debug_brc20():
    addr = request.args.get("addr", "")
    return jsonify({"addr": addr, "brc20": fetch_brc20_balances(addr)})


if __name__ == "__main__":
    # DEBUG: list routes
    for rule in app.url_map.iter_rules():
        print(rule)
    app.run(debug=True)