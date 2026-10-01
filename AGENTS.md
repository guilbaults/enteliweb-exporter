# enteliweb-exporter

## Project Overview

A Prometheus exporter for Johnson Controls Enteliweb building management systems. It connects to an Enteliweb server, discovers BACnet points on controllers, and exposes their values as Prometheus gauges.

**Language:** Python 3 (single-file application: `enteliweb-exporter.py`)  
**Dependencies:** `requests`, `beautifulsoup4`  
**License:** Apache 2.0

### Architecture

One exporter process serves all controllers. Prometheus drives the scrape loop and passes the controller reference via `?controller=` query parameter. The exporter handles login, CSRF tokens, session expiry, and point discovery transparently.

Key classes:
- **`EnteliwebExporter`** — Manages the Enteliweb session (login, CSRF, point discovery, value fetching)
- **`MetricsHandler`** — HTTP request handler for `/metrics` and `/health` endpoints
- **`BoundedThreadPoolHTTPServer`** — HTTP server with a fixed-size thread pool (avoids unbounded thread creation)

### Metrics Output

Single metric with labels:
```
enteliweb_value{bacnet_id="<ref>", label="<name>"} <value>
```

Scraped via: `GET /metrics?controller=//site/10000`

## Configuration

Copy `config.ini.dist` to `config.ini` and fill in credentials:

```ini
[enteliweb]
host = https://your-enteliweb-server
username = user
password = changeme
insecure = false

[exporter]
port = 8085
discovery_ttl = 3600
max_workers = 50
```

Multiple config variants exist for different environments (e.g., `config.ini.ets`, `config.ini.ul`).

## Building and Running

```bash
# Install dependencies
pip install requests beautifulsoup4

# Run the exporter
python enteliweb-exporter.py config.ini

# With debug logging
python enteliweb-exporter.py config.ini --log-level DEBUG

# Fetch controller programs (one-shot, exits after saving)
python enteliweb-exporter.py config.ini --get-programs //site/10000
```

## CI/CD

- **GitHub Actions:** `.github/workflows/lint.yml` runs flake8 on push/PR to `main` or `master`
- **Lint:** `flake8 --max-line-length=120 enteliweb-exporter.py`

## Key Files

| File | Purpose |
|------|---------|
| `enteliweb-exporter.py` | Main application (single-file Python script) |
| `config.ini.dist` | Configuration template |
| `prometheus.yml.example` | Prometheus scrape config example |
| `requirements-lint.txt` | Lint dependencies (flake8) |

## Development Conventions

- **Line length:** 120 characters max (enforced by flake8)
- **Single-file architecture:** All code lives in `enteliweb-exporter.py` — no separate modules
- **No test suite:** Tests would need to be written from scratch if desired
- **Config files:** Environment-specific configs use suffix naming (e.g., `config.ini.ets` for ETS environment)
- **Programs output:** `--get-programs` saves controller programs to `controller_programs/` directory
- **Discovery caching:** Points are cached per controller with randomized TTL (±50% of configured `discovery_ttl`)
- **Thread safety:** Uses `threading.RLock` to protect shared state during concurrent scrapes

## Important Notes

- The exporter **requires** `?controller=` parameter on `/metrics` — returns 400 without it
- Discovery is serialized to avoid duplicate API calls for the same controller
- Session expiry (401) is handled automatically with re-login
- `BoundedThreadPoolHTTPServer` prevents thread exhaustion under high concurrency
- CSRF tokens are refreshed on each login and as needed during operations
