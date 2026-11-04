# XHTTP Real Delay Checker

The checker downloads its input automatically from:

`https://github.com/williamnecoo1-pixel/testrw/raw/refs/heads/main/reality_configs.txt`

It does not edit or push anything to the source repository. It only tests the downloaded links and uploads result files as a GitHub Actions artifact.

## Filters
- VLESS, VMess, Trojan
- XHTTP transport
- TLS security
- Port 443

## Tests
- Google: `https://www.google.com/generate_204` (HTTP 204)
- Cloudflare: `https://cp.cloudflare.com/generate_204` (HTTP 204)
- Apple: `http://captive.apple.com/hotspot-detect.html` (HTTP 200 with `Success` in body)

A config is marked **WORKING if at least one endpoint returns its expected response**. Each endpoint result is recorded separately.

## Outputs
- `working_configs.txt`: links that passed at least one test, sorted by delay
- `failed_configs.txt`: links that did not pass
- `results.csv`: per-endpoint status and measured delay

Download these from the `xhttp-check-results` artifact attached to each workflow run.

## Run
Push the checker files to a new GitHub repository, then use **Actions → XHTTP Real Delay Checker → Run workflow**. It also runs every six hours.
