# FortiDoc

FortiDoc takes a FortiGate config export (`.conf` or `.yaml`) and turns it into a single HTML report. You get every interface, policy, route, VPN tunnel and object, plus an executive summary and a set of CIS benchmark findings with remediation steps.

If you upload two configs instead of one, it produces a diff showing what was added, removed or changed at field level. Objects are matched by identity rather than position, so FortiOS renumbering its `edit N` blocks doesn't flood the diff with changes that aren't real.

A few things worth knowing up front:

- It runs in your own container. The config is parsed locally and never leaves the machine.
- Nothing is persisted. There's no database, and the only output is the HTML file you download.
- The report is fully self-contained. CSS and JS are inlined, there are no external fonts or CDNs, and it works offline.

## Quick start

```bash
git clone https://github.com/escheming/MAIN-FortiDoc.git fortidoc
cd fortidoc
docker compose up -d
```

Open http://localhost:8080.

On the first start, FortiDoc generates an admin password and an API key and prints them to the container log once:

```bash
docker logs fortidoc
```

Both are saved on the `fortidoc-settings` volume and reused on every later start. If you'd rather choose your own, set `ADMIN_PASSWORD` and/or `API_KEY` (see [Configuration](#configuration)). Environment variables always take precedence.

The web UI has four pages:

| Page | Purpose |
|---|---|
| `/report` | Upload one config, download the report |
| `/diff` | Upload two configs, download the change report |
| `/admin` | Adjust what the report contains |
| `/docs` | API reference |

## The report

- **Executive summary:** HA status, firmware version, policy counts and a super admin audit.
- **Security findings:** 16+ CIS benchmark checks (SNMP, NTP, weak crypto, open admin access and more). Each one has a severity, references, remediation steps and the exact config lines that triggered it.
- **Firewall policies:** action, in/out interfaces, sources, destinations, services and security profiles for every policy.
- **Network:** physical and virtual interfaces, VLANs, zones, DHCP, static and policy routes, BGP and OSPF.
- **VPN:** IPsec phase1/phase2, site-to-site tunnels, SSL-VPN portals and realms, split tunneling.
- **Objects:** addresses, groups, services, VIPs and IP pools, with usage counters. Clicking an object shows which policies reference it.
- **System:** admins, DNS, NTP, SNMP, SD-WAN, certificates and traffic shapers.

## Config diff (FortiCompare)

Upload a before and an after export. The diff engine matches objects by identity:

- Named policies are matched by name, unnamed ones by a signature of their content.
- Reordering values is not treated as a change.
- When FortiOS renumbers every `edit N` because something moved, a renumber-only change shows up as one "renumbered" note instead of roughly 1,000 false changes.

The output starts with a change index showing counts per section. Added and removed objects are listed in compact tables, and changed policies appear as cards grouped by field (Traffic, Access, Security profiles) with the old and new values.

## Admin settings

The password-protected `/admin` page lets you:

- turn report sections on or off
- disable built-in findings and override their severity or remediation text
- add custom findings, either as free text or as pattern-based checks that only fire when a given string appears in the config (the matching lines are shown as evidence)
- export and import the full settings as JSON

## API

For automation such as monthly config reports or change detection in CI:

| Endpoint | Description |
|---|---|
| `POST /api/v1/report` | Upload a config, receive the report HTML as an attachment |
| `POST /api/v1/diff` | Upload two configs, receive the diff HTML as an attachment |
| `POST /api/v1/diff/summary` | Upload two configs, receive a JSON summary with per-section counts |
| `GET /api/v1/health` | Liveness probe (no key required) |

Authenticate with an `X-API-Key` header. The running app serves a full reference with curl examples at `/docs`.

## Configuration

All configuration is done through environment variables, and all of them are optional. `ADMIN_PASSWORD` and `API_KEY` are generated on first start and stored on the settings volume, so there's nothing you need to set up. Only define them if you want to manage the values yourself or enable SSO.

| Variable | Description |
|---|---|
| `ADMIN_PASSWORD` | Password for the `/admin` UI (auto-generated on first start) |
| `API_KEY` | Key for `X-API-Key` authentication (auto-generated on first start) |
| `OIDC_ENABLED` | Set to `1` to enable SSO. `OIDC_CLIENT_ID` and `OIDC_ISSUER` are also required |
| `OIDC_ISSUER` | OIDC issuer URL, e.g. `https://auth.example.com/application/o/fortidoc/` |
| `OIDC_CLIENT_ID` | OIDC client ID (public PKCE client) |
| `OIDC_CLIENT_SECRET` | OIDC client secret (can be empty for public clients) |
| `OIDC_PUBLIC_BASE` | Public base URL of the app, e.g. `https://fortidoc.example.com`. The callback is always `<base>/oidc/callback`, so use that as the redirect URI in your IdP |
| `OIDC_ADMIN_EMAILS` | Comma-separated list of SSO emails allowed to become admin. If empty, any SSO user can |

To use your own values, create a `.env` file next to `docker-compose.yml`:

```bash
ADMIN_PASSWORD=your-password
API_KEY=your-api-key
OIDC_ENABLED=1
OIDC_ISSUER=https://auth.example.com/application/o/fortidoc/
OIDC_CLIENT_ID=your-client-id
OIDC_PUBLIC_BASE=https://fortidoc.example.com
```

`docker compose` reads it automatically on the next `docker compose up -d`.

Settings and generated credentials live on the `fortidoc-settings` volume. Deleting the volume resets everything to factory defaults and generates new credentials, which are printed to the log again.

## Supported config sections

- `system global`, `system interface`, `system admin`, `system dns`, `system ntp`, `system snmp`, `system ha`, `system sdwan`, `system dhcp`
- `router static`, `router policy`, `router bgp`, `router ospf`
- `firewall address`, `firewall addrgrp`, `firewall service custom`, `firewall service group`, `firewall policy`
- `firewall vip`, `firewall ippool`
- `firewall shaper traffic-shaper`, `firewall shaper per-ip-shaper`, `firewall shaping-policy`
- `vpn ipsec phase1-interface`, `vpn ipsec phase2-interface`, `vpn ssl settings`, `vpn ssl web portal`
- `vpn certificate local`

Encrypted `#FGBK` backups are detected and rejected with a clear error. Export the config unencrypted (plain text starting with `#config-version=`) and the report will build.

## Requirements

Docker, or Python 3.11+ with Flask, Gunicorn and PyYAML.

## Project layout

```
├── fgdoc.py          Pipeline entry point (parse → extract → findings → render)
├── parser.py         Tokenizer and recursive config parser
├── extractors.py     20+ extract_* functions covering all config sections
├── findings.py       CIS benchmark checks and finding settings
├── analysis.py       Unused object detection
├── diff.py           Identity-based config diff engine
├── settings.py       Global report settings
├── oidc.py           Optional OIDC SSO for the admin UI
├── yaml_config.py    FortiGate YAML export → FortiOS text
├── renderers.py      HTML renderers and report builder
├── app.py            Flask web UI and API
├── templates/        UI and generated report templates
├── static/           Report CSS/JS, favicon
└── input/ output/    CLI-mode folders
```

## License

Apache-2.0 — see [LICENSE](LICENSE). The included [NOTICE](NOTICE) file carries the attribution that Apache-2.0 requires you to keep with the product.