
# XHTTP Real Delay Checker

This repository tests share links in `reality_configs.txt` using the official Xray Core binary.

## Filters
- VLESS, VMess, Trojan
- XHTTP transport
- TLS security
- Port 443

## Tests
- Google: `https://www.google.com/generate_204` (HTTP 204)
- Cloudflare: `https://cp.cloudflare.com/generate_204` (HTTP 204)
- Apple: `http://captive.apple.com/hotspot-detect.html` (HTTP 200 with `Success` in body)

A config is marked **WORKING if at least one of the three endpoints returns its expected response**.
All three outcomes are recorded in `results.csv`. `delay_ms` is the median of successful endpoint timings.

## Files
- `reality_configs.txt`: input links, one per line
- `working_configs.txt`: links that passed at least one test, sorted by delay
- `failed_configs.txt`: links that did not pass
- `results.csv`: per-endpoint status and measured delay

## Run
Push `main.py`, `requirements.txt`, this workflow, and `reality_configs.txt` to the repository, then use **Actions → XHTTP Real Delay Checker → Run workflow**.

The workflow runs every six hours. Set `WORKERS` in the workflow to change parallelism.
