# PV NodeJS Layer 7 Load Tester & HTTP/2 Attack Tool

**pv_http.js** is a Node.js script for Layer 7 load testing and security auditing. It supports HTTP/1.1, HTTP/2, and HTTP/3, with a standard load mode that mimics browser traffic and two HTTP/2 attack modes for resilience checks.

HTTP/2 attack implementations:

- **Rapid Reset** (`--attack rapid-reset`) — CVE-2023-44487 (client-side stream cancel)
- **MadeYouReset** (`--attack madeyoureset`) — CVE-2025-54500 (oversized DATA frame → server RST)

# Deflect Bypass ✅
![image](https://raw.githubusercontent.com/pinoyvendetta/pv-nodejs-layer-7/refs/heads/main/img/deflect.png)
# Cloudflare 403 Response Bypass ✅
![image](https://raw.githubusercontent.com/pinoyvendetta/pv-nodejs-layer-7/refs/heads/main/img/cloudflare-bypass.png)

---

## Features

- **Split engines by protocol**
  - **HTTP/1.1 & HTTP/2** → [undici](https://github.com/nodejs/undici) (native), with optional TLS parameter shuffle (`--ja3-evasion`)
  - **HTTP/3** → [impers](https://www.npmjs.com/package/impers) / curl-impersonate (real browser JA3/JA4). On failure → logged **FALLBACK→H2**; after repeated fails → short **cooldown** then retry H3
- **Dual HTTP/2 attack modes** (native `http2` module)
- **Realistic traffic**: random User-Agent / Referer / Accept, burst + think time, optional adaptive delay on blocking status codes
- **Advanced burst mode** with configurable size and think-time multiplier
- **Retries** with exponential backoff
- **Real-time CLI dashboard**: RPS, latency (avg / p50 / p95), status counts per protocol, recent log

![image](https://raw.githubusercontent.com/pinoyvendetta/pv-nodejs-layer-7/refs/heads/main/img/pv-nodejs-l7.png)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
![image](https://raw.githubusercontent.com/pinoyvendetta/pv-nodejs-layer-7/refs/heads/main/img/pv-nodejs-madeyoureset.png)

---

## Install

```sh
npm install undici yargs chalk@4 impers
```

**Notes:**

- Use **`chalk@4`** (chalk v5+ is ESM-only and breaks this CommonJS script).
- **impers** is ESM-only; the script loads it with dynamic `import()` (Node **≥ 18**).
- impers may download the curl-impersonate binary on first H3 use (needs network).
- Run the script from the directory where you ran `npm install`.

---

## Usage

```sh
node pv_http.js --url <target-url> [options]
```

### Options

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--url` | `-u` | Target URL (**required**) | |
| `--time` | `-t` | Duration in minutes (1–1440) | `1` |
| `--conc` | `-c` | Concurrent workers (1–10000) | `50` |
| `--attack` | `-a` | `none` \| `rapid-reset` \| `madeyoureset` | `none` |
| `--protocol` | `-p` | Protocols to use, e.g. `"1.1,2,3"` | auto (`h2`, or `h3` if `-h3`) |
| `--adaptive-delay` | `-ad` | Back off on 401/403/429/etc. | `false` |
| `--adv-burst` | `-ab` | Advanced burst + think mode | `false` |
| `--burst-size` | `-bs` | Max burst size when `--adv-burst` is on | — |
| `--think-multiplier` | `-tm` | Think-time multiplier for advanced bursts (0.0–2.0) | — |
| `--max-retries` | `-mr` | Max retries per request on error | `2` |
| `--retry-base-ms` | `-rb` | Base backoff (ms) for exponential retries | `150` |
| `--ja3-evasion` | `-ja3` | TLS shuffle on H1/H2; browser profiles on H3 | `true` |
| `--impersonate` | `-imp` | Fixed impers profile (e.g. `chrome131`) | random |
| `--force-http3` | `-h3` | Prefer / include HTTP/3 | `false` |
| `--help` | `-h` | Show help | |

### Examples

```sh
# H1 + H2 + H3, 30 workers, 2 minutes
node pv_http.js -u https://example.com -p "1.1,2,3" -t 2 -c 30

# Adaptive delay + advanced bursts
node pv_http.js -u https://example.com -p "1.1,2,3" -ad -ab -tm 2 -bs 30

# H3 only (impers); falls back to H2 on failure
node pv_http.js -u https://example.com -h3 -c 20

# Fixed Chrome fingerprint for H3
node pv_http.js -u https://example.com -p "3" --impersonate chrome131

# Rapid Reset attack
node pv_http.js -u https://example.com -a rapid-reset

# MadeYouReset attack
node pv_http.js -u https://example.com -a madeyoureset
```

---

## Architecture

| Protocol | Client | Fingerprint |
|----------|--------|-------------|
| **H1** | undici | Optional TLS cipher/sigalg/curve shuffle (`--ja3-evasion`); ALPN forced to `http/1.1` |
| **H2** | undici | Same shuffle; ALPN prefers `h2` |
| **H3** | impers | Real browser JA3/JA4 via curl-impersonate. Fail → **FALLBACK→H2**; 3 fails → **5s cooldown** then retry H3 |
| **Attacks** | native `http2` | Weak TLS shuffle only (needs low-level RST control) |

At startup the script prints active flags, e.g.:

```text
Flags: ja3=true adaptive-delay=true adv-burst=true think-mult=2 force-h3=false max-retries=2
Workers per protocol: H1=10, H2=10, H3=10
```

---

## Requirements

- **Node.js** ≥ 18
- **Packages:** `undici`, `yargs`, `chalk@4`, `impers` (optional but required for real H3)

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Missing dependency: undici` | `npm install undici` in the script directory |
| `impers not available` / H3 always fallback | `npm install impers` (Node ≥ 18) |
| `chalk.red is not a function` | `npm install chalk@4` |
| Only one protocol in stats | Pass `-p "1.1,2,3"` and confirm startup shows workers per protocol |
| H3 works briefly then stops | Expected under load: cooldown + H2 fallback; watch for `FALLBACK→H2` / `COOLDOWN` in the log |

---

## Legal / Ethics Notice

> **This tool is for educational, research, or authorized security testing on systems you own or have explicit permission to test. Unauthorized use against targets is illegal and unethical. The author is not responsible for misuse.**
