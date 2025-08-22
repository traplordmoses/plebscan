// cargo.toml (deps you need)
// anyhow = "1"
// bitcoin = { version = "0.32", features = ["base64"] }
// clap = { version = "4", features = ["derive"] }
// dotenv = "0.15"
// reqwest = { version = "0.11", features = ["json", "gzip", "brotli", "deflate", "stream", "rustls-tls"] }
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"
// tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }

use anyhow::{bail, Context, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::key::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use clap::{Parser, ValueEnum};
use dotenv::dotenv;
use reqwest::{header, Client, RequestBuilder, StatusCode};
use serde::Serialize;
use serde_json::Value;
use std::io::{stdin, stdout, Write};
use std::str::FromStr;
use tokio::time::{sleep, Duration};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Purpose { P44, P49, P84, P86 }

#[derive(Parser, Debug)]
#[command(name = "pleb_scan", version, about)]
struct Args {
    #[arg(long, value_enum, default_value_t = Purpose::P86)]
    purpose: Purpose,
    #[arg(long, default_value_t = 200)]
    max: u32,
    #[arg(long = "miss-limit", default_value_t = 20)]
    miss_limit: u32,
    #[arg(long, default_value_t = 0)]
    chain: u32,
    #[arg(long = "sleep-ms", default_value_t = 100)]
    sleep_ms: u64,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    with_alkanes: bool,
    #[arg(long = "with-runes", default_value_t = true, action = clap::ArgAction::Set)]
    with_runes: bool,
    #[arg(long, default_value = "https://open-api.unisat.io")]
    unisat_base: String,
    #[arg(long, env = "UNISAT_API_KEY")]
    unisat_api_key: Option<String>,
    #[arg(long, default_value = "https://api.hiro.so")]
    base_url: String,
    #[arg(long, env = "HIRO_API_KEY")]
    api_key: Option<String>,
    #[arg(long, default_value = "results.json")]
    output: String,
    #[arg(long, default_value = "bitcoin")]
    network: String,
    #[arg(long, env = "XPUB")]
    xpub: Option<String>,
    #[arg(long)]
    verbose: bool,
    #[arg(long, value_name = "BTC_ADDRESS")]
    address: Option<String>,
}

#[derive(Serialize, Clone)]
struct AlkaneHolding {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,                 // e.g. "2:0"
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,             // e.g. "DIESEL"
    #[serde(skip_serializing_if = "Option::is_none")]
    decimals: Option<u32>,              // usually 8 on UniSat
    amount: String,                     // base units as integer string
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_hr: Option<String>,          // NEW: human-readable (e.g. "0.43724184")
    #[serde(skip_serializing_if = "Option::is_none")]
    ordiscan_url: Option<String>,       // NEW: link to Ordiscan detail
}

#[derive(Serialize)]
struct WalletItem {
    pubkey: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    inscription_ids: Vec<String>,
    inscription_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    runes: Vec<RuneHolding>,
    runes_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    alkanes: Vec<AlkaneHolding>,
    alkanes_count: usize,
}

#[derive(Serialize, Clone)]
struct RuneHolding {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    spaced_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    balance: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let args = Args::parse();

    let client = build_client(args.api_key.clone())?;
    let base = base_for_network(&args.base_url, &args.network)?;
    let verbose = args.verbose;

    // ---------- SINGLE ADDRESS ----------
    if let Some(addr) = args.address.as_deref() {
        Address::from_str(addr).context("--address is not a valid Bitcoin address")?;
        let item = scan_address(&client, &base, addr, verbose, &args.api_key, args.with_runes,&args.unisat_base, &args.unisat_api_key, args.with_alkanes).await?;
        write_and_print(&args.output, vec![item])?;
        return Ok(());
    }

    // ---------- XPUB SCAN ----------
    let xpub_str = args
        .xpub
        .unwrap_or_else(|| prompt("please enter your xpub key: ").expect("failed to read xpub"));
    reject_slip132(&xpub_str)?;

    let network = match args.network.to_lowercase().as_str() {
        "bitcoin" | "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        other => bail!("unsupported network: {other}"),
    };

    let xpub = Xpub::from_str(&xpub_str).context("failed to parse xpub")?;
    enforce_xpub_network(&xpub, network)?;

    let secp = Secp256k1::verification_only();
    let base_path = DerivationPath::from(vec![]);
    let mut wallets: Vec<WalletItem> = Vec::new();
    let mut misses = 0u32;
    let mut i = 0u32;

    while i < args.max && misses < args.miss_limit {
        let path = base_path.extend([
            ChildNumber::Normal { index: args.chain }, // 0=receive, 1=change
            ChildNumber::Normal { index: i },
        ]);
        let child = xpub
            .derive_pub(&secp, &path)
            .with_context(|| format!("derive path {path:?} failed"))?;
        let addr = addr_from_child(&secp, network, args.purpose, &child.public_key)
            .context("address derivation failed")?;

        let ids = get_inscription_ids(&client, &base, &addr, verbose, &args.api_key)
            .await
            .unwrap_or_default();
        let inscription_count = ids.len();

        let runes = if args.with_runes {
            get_runes_balances(&client, &base, &addr, verbose, &args.api_key)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let runes_count = runes.len();

        let alkanes = if args.with_alkanes {
            get_alkanes_balances_unisat(
                &client, &args.unisat_base, &addr, verbose, &args.unisat_api_key
            ).await.unwrap_or_default()
        } else { Vec::new() };
        let alkanes_count = alkanes.len();

        if inscription_count > 0 || runes_count > 0 || alkanes_count > 0 {
            wallets.push(WalletItem {
                pubkey: addr,
                inscription_ids: ids,
                inscription_count,
                runes,
                runes_count,
                alkanes,         
                alkanes_count,   
            });
            misses = 0;
        } else {
            misses += 1;
        }

        i += 1;
        sleep(Duration::from_millis(args.sleep_ms)).await;
    }

    if misses >= args.miss_limit {
        eprintln!("no results for {} consecutive addresses — stopping.", args.miss_limit);
    }

    write_and_print(&args.output, wallets)?;
    Ok(())
}

// -------- single-address helper --------
async fn scan_address(
    client: &Client,
    base_url: &str,
    address: &str,
    verbose: bool,
    api_key: &Option<String>,
    with_runes: bool,
    // add these params so main() can pass them down
    unisat_base: &str,
    unisat_api_key: &Option<String>,
    with_alkanes: bool,
) -> Result<WalletItem> {
    let inscription_ids = get_inscription_ids(client, base_url, address, verbose, api_key)
        .await
        .unwrap_or_default();
    let inscription_count = inscription_ids.len();

    let runes = if with_runes {
        get_runes_balances(client, base_url, address, verbose, api_key)
            .await
            .unwrap_or_default()
    } else { Vec::new() };
    let runes_count = runes.len();

    let alkanes = if with_alkanes {
        get_alkanes_balances_unisat(client, unisat_base, address, verbose, unisat_api_key)
            .await
            .unwrap_or_default()
    } else { Vec::new() };
    let alkanes_count = alkanes.len();

    Ok(WalletItem {
        pubkey: address.to_string(),
        inscription_ids,
        inscription_count,
        runes,
        runes_count,
        alkanes,
        alkanes_count,
    })
}


// -------- utils --------
fn base_for_network(base: &str, network: &str) -> Result<String> {
    let b = base.trim_end_matches('/').to_string();
    match network.to_lowercase().as_str() {
        "testnet" => Ok(format!("{}/testnet", b)),
        "bitcoin" | "mainnet" => Ok(b),
        other => bail!("unsupported network: {other}"),
    }
}

fn find_alkane_id_fallback(item: &serde_json::Value) -> Option<String> {
    // try common keys first
    let candidates = [
        "alkaneId", "tokenId", "id", "aid", "index", "tickId", "alkane_id", "token_id",
    ];
    for k in candidates {
        if let Some(s) = item.get(k).and_then(|x| x.as_str()) {
            if s.contains(':') { return Some(s.to_string()); }
        }
    }

    // brute-force: scan all string fields for something like "number:number"
    let re = regex::Regex::new(r"^\d+:\d+$").ok()?;
    if let Some(obj) = item.as_object() {
        for (_k, v) in obj {
            if let Some(s) = v.as_str() {
                if re.is_match(s) { return Some(s.to_string()); }
            }
        }
    }
    None
}

fn prompt(s: &str) -> Result<String> {
    print!("{s}");
    stdout().flush()?;
    let mut input = String::new();
    stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn reject_slip132(s: &str) -> Result<()> {
    let lower = s.to_lowercase();
    let bad = ["zpub", "ypub", "upub", "vpub"];
    if bad.iter().any(|p| lower.starts_with(p)) {
        bail!("got a SLIP-132 pubkey ({s}). Please supply a standard xpub/tpub for BIP84/BIP86.");
    }
    Ok(())
}

fn enforce_xpub_network(xpub: &Xpub, selected: Network) -> Result<()> {
    let s = xpub.to_string();
    let is_test = s.starts_with("tpub") || s.starts_with("upub") || s.starts_with("vpub");
    let xpub_net = if is_test { Network::Testnet } else { Network::Bitcoin };
    if xpub_net != selected {
        bail!("xpub network ({xpub_net:?}) does not match --network ({selected:?})");
    }
    Ok(())
}

fn build_client(api_key: Option<String>) -> Result<Client> {
    let mut headers = header::HeaderMap::new();
    headers.insert(header::ACCEPT, header::HeaderValue::from_static("application/json"));
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static("pleb_scan/0.1"));
    if let Some(k) = api_key.clone() {
        headers.insert("x-api-key", header::HeaderValue::from_str(&k)?);
        headers.insert("X-API-Key", header::HeaderValue::from_str(&k)?);
    }
    Ok(Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(4))
        .build()?)
}

fn addr_from_child(
    secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    network: Network,
    purpose: Purpose,
    child_pk: &bitcoin::secp256k1::PublicKey,
) -> Result<String> {
    let pk = PublicKey::from(*child_pk);
    Ok(match purpose {
        Purpose::P44 => Address::p2pkh(&pk, network).to_string(),
        Purpose::P49 => Address::p2shwpkh(&pk, network)?.to_string(),
        Purpose::P84 => Address::p2wpkh(&pk, network)?.to_string(),
        Purpose::P86 => {
            let (xonly, _) = child_pk.x_only_public_key();
            Address::p2tr(secp, xonly, None, network).to_string()
        }
    })
}

fn human_amount_str(amount_units: &str, decimals: u32) -> String {
    let mut s = amount_units.trim_start_matches('+').trim_start_matches('0').to_string();
    if s.is_empty() { s.push('0'); }  // treat "0" correctly
    let d = decimals as usize;
    if s.len() <= d {
        let zeros = "0".repeat(d - s.len());
        s = format!("0.{}{}", zeros, s);
    } else {
        let split = s.len() - d;
        s.insert(split, '.');
    }
    // trim trailing zeros and any trailing dot
    while s.contains('.') && s.ends_with('0') { s.pop(); }
    if s.ends_with('.') { s.pop(); }
    s
}

// ---------- HTTP w/ retry ----------
async fn get_json_with_backoff(req: RequestBuilder, attempts: usize, verbose: bool) -> Result<Value> {
    let mut delay = Duration::from_millis(400);
    let mut last_err: Option<anyhow::Error> = None;

    for try_no in 1..=attempts {
        let resp = match req.try_clone().expect("cloneable request").send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(e.into());
                if try_no == attempts { break; }
                tokio::time::sleep(delay).await; delay *= 2; continue;
            }
        };

        let status = resp.status();
        let bytes = resp.bytes().await?;
        if status == StatusCode::TOO_MANY_REQUESTS {
            if try_no == attempts { bail!("rate limited after {attempts} attempts"); }
            if verbose { eprintln!("429 received; backing off {} ms", delay.as_millis()); }
            tokio::time::sleep(delay).await; delay *= 2; continue;
        }
        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes);
            last_err = Some(anyhow::anyhow!("http {}: {}", status, body));
            if try_no == attempts { break; }
            tokio::time::sleep(delay).await; delay *= 2; continue;
        }
        let v: Value = serde_json::from_slice(&bytes)?;
        return Ok(v);
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("exhausted retries")))
}

// ---------- API: inscriptions ----------
async fn get_inscription_ids(
    client: &Client, base: &str, address: &str, verbose: bool, api_key: &Option<String>,
) -> Result<Vec<String>> {
    const LIMIT: u32 = 60;
    let endpoint = format!("{base}/ordinals/v1/inscriptions");

    fn extract_ids_for_address(v: &Value, want: &str) -> Vec<String> {
        if let Some(arr) = v.get("results").and_then(|x| x.as_array()) {
            return arr.iter()
                .filter(|it| {
                    it.get("address").and_then(|x| x.as_str()) == Some(want)
                    || it.get("genesis_address").and_then(|x| x.as_str()) == Some(want)
                })
                .filter_map(|it| it.get("id").and_then(|x| x.as_str()).map(str::to_owned))
                .collect();
        }
        Vec::new()
    }

    async fn fetch_page(
        client: &Client, url: &str, params: &[(&str, String)], verbose: bool, api_key: &Option<String>,
    ) -> Result<Value> {
        let query: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut req = client.get(url).query(&query);
        if let Some(key) = api_key { req = req.header("x-api-key", key); }
        get_json_with_backoff(req, 3, verbose).await
    }

    let mut all: Vec<String> = Vec::new();
    let mut offset: u32 = 0u32;

    loop {
        let params = vec![
            ("address", address.to_string()),
            ("limit", LIMIT.to_string()),
            ("offset", offset.to_string()),
        ];
        let page = match fetch_page(client, &endpoint, &params, verbose, api_key).await {
            Ok(v) => v,
            Err(e) => { eprintln!("error querying {address}: {e}"); break; }
        };
        if verbose { eprintln!("inscriptions page @ {offset} for {address}: {:#}", page); }

        let ids = extract_ids_for_address(&page, address);
        if ids.is_empty() { break; }

        all.extend(ids);
        offset += LIMIT;

        if let Some(t) = page.get("total").and_then(|t| t.as_u64()) {
            if (offset as u64) >= t { break; }
        }
    }

    all.sort(); all.dedup();
    Ok(all)
}

// ---------- API: runes balances ----------
async fn get_runes_balances(
    client: &Client,
    base: &str,
    address: &str,
    verbose: bool,
    api_key: &Option<String>,
) -> Result<Vec<RuneHolding>> {
    let base = base.trim_end_matches('/');
    let url = format!("{}/runes/v1/addresses/{}/balances", base, address);

    let mut out: Vec<RuneHolding> = Vec::new();
    let mut offset: u32 = 0;
    const LIMIT: u32 = 60; // Hiro max

    loop {
        let mut req = client
            .get(&url)
            .query(&[
                ("offset", offset.to_string()),
                ("limit", LIMIT.to_string()),
            ]);

        if let Some(key) = api_key {
            req = req.header("x-api-key", key);
        }

        let page = get_json_with_backoff(req, 3, verbose).await?;
        if verbose {
            eprintln!("RUNES balances offset {} for {}: {:#}", offset, address, page);
        }

        let total = page.get("total").and_then(|t| t.as_u64()).unwrap_or(0);
        let results = page
            .get("results")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();

        if results.is_empty() {
            break;
        }

        for item in results {
            let balance = item
                .get("balance")
                .and_then(|x| x.as_str())
                .unwrap_or("0")
                .to_string();

            let rune = item.get("rune").and_then(|x| x.as_object());
            let (name, spaced_name, id) = if let Some(r) = rune {
                (
                    r.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    r.get("spaced_name").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    r.get("id").and_then(|x| x.as_str()).map(|s| s.to_string()),
                )
            } else { ("".to_string(), None, None) };

            if !name.is_empty() {
                out.push(RuneHolding { name, spaced_name, id, balance });
            }
        }

        offset += LIMIT;
        if total > 0 && (offset as u64) >= total {
            break;
        }
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

async fn get_alkanes_balances_unisat(
    client: &Client,
    unisat_base: &str,
    address: &str,
    verbose: bool,
    unisat_api_key: &Option<String>,
) -> Result<Vec<AlkaneHolding>> {
    let base = unisat_base.trim_end_matches('/');
    let url = format!("{}/v1/indexer/address/{}/alkanes/token-list", base, address);

    let mut out: Vec<AlkaneHolding> = Vec::new();
    let mut start: u32 = 0;
    const LIMIT: u32 = 100;

    loop {
        // UniSat uses Bearer auth; params are usually start/limit
        // ref: Open API docs & examples (Bearer) and rate limits. 
        // https://docs.unisat.io/dev/open-api-documentation  (auth, base urls, limits)
        let mut req = client
            .get(&url)
            .query(&[("start", start.to_string()), ("limit", LIMIT.to_string())])
            .header(header::ACCEPT, "application/json");

        if let Some(key) = unisat_api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        let page = match get_json_with_backoff(req, 3, verbose).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error querying UniSat Alkanes for {}: {}", address, e);
                break;
            }
        };

        if verbose {
            eprintln!("ALKANES token-list start={} for {}: {:#}", start, address, page);
        }

        // Most UniSat “list” endpoints look like:
        // { code, msg, data: { total, list: [...] } }
        // but sometimes older ones used "detail". Handle both.
        let list = page
            .get("data")
            .and_then(|d| d.get("list").or_else(|| d.get("detail")))
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();

        if list.is_empty() {
            break;
        }

        for item in list {
            // amount in base units
            let amount = item
                .get("amount")
                .or_else(|| item.get("balance"))
                .and_then(|x| x.as_str())
                .unwrap_or("0")
                .to_string();

            // robust id extraction (e.g., "2:0")
            let id = item
                .get("alkaneId")
                .or_else(|| item.get("tokenId"))
                .or_else(|| item.get("id"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .or_else(|| find_alkane_id_fallback(&item));

            // "DIESEL", etc.
            let symbol = item
                .get("symbol")
                .or_else(|| item.get("ticker"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());

            // default 8 if missing
            let decimals = item
                .get("divisibility")
                .or_else(|| item.get("decimals"))
                .and_then(|x| x.as_u64())
                .map(|n| n as u32)
                .or(Some(8));

            // human-readable amount
            let amount_hr = Some(human_amount_str(&amount, decimals.unwrap_or(8)));

            // Ordiscan URL prefers {SYMBOL}/{ID} when both exist
            let ordiscan_url = match (symbol.as_ref(), id.as_ref()) {
                (Some(sym), Some(tid)) => Some(format!("https://ordiscan.com/alkane/{}/{}", sym, tid)),
                (Some(sym), None)      => Some(format!("https://ordiscan.com/alkane/{}", sym)),
                (None, Some(tid))      => Some(format!("https://ordiscan.com/alkane/{}", tid)),
                _                      => None,
            };

            out.push(AlkaneHolding {
                id,
                symbol,
                decimals,
                amount,
                amount_hr,
                ordiscan_url,
            });
        }


        start += LIMIT;

        if let Some(total) = page
            .get("data")
            .and_then(|d| d.get("total"))
            .and_then(|t| t.as_u64())
        {
            if (start as u64) >= total {
                break;
            }
        }
    }

    out.sort_by(|a, b| a.symbol.cmp(&b.symbol));
    Ok(out)
}

// ---------- write ----------
fn write_and_print(path: &str, wallets: Vec<WalletItem>) -> Result<()> {
    #[derive(Serialize)]
    struct Out { wallets: Vec<WalletItem> }

    let json_pretty = serde_json::to_string_pretty(&Out { wallets })?;
    println!("{json_pretty}");
    std::fs::write(path, json_pretty)?;
    eprintln!("json written to {}", path);
    Ok(())
}