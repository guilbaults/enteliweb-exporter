# enteliweb-exporter

A Prometheus exporter for Johnson Controls Enteliweb building management systems.

It connects to an Enteliweb server, discovers BACnet points on controllers, and exposes their values as Prometheus gauges.

## Prerequisites

- Python 3
- `requests`
- `beautifulsoup4`

Install dependencies:

```bash
pip install requests beautifulsoup4
```

## Configuration

Copy `config.ini.dist` to `config.ini` and fill in your Enteliweb credentials:

```ini
[enteliweb]
host = https://your-enteliweb-server
username = user
password = changeme
insecure = false

[exporter]
port = 8085
discovery_ttl = 3600
```

| Section | Key | Description |
|---|---|---|
| `[enteliweb]` | `host` | URL of the Enteliweb server (e.g. `https://enteliweb.example.com`) |
| | `username` | Enteliweb username |
| | `password` | Enteliweb password |
| | `insecure` | Set to `true` to skip TLS certificate verification |
| `[exporter]` | `port` | Port the metrics HTTP server listens on |
| | `discovery_ttl` | How long (seconds) to cache the discovered points per controller (default `3600`) |

## Running

```bash
python enteliweb-exporter.py config.ini
```

The exporter starts an HTTP server on the configured port and stays running.

### Logging

Control log verbosity with `--log-level`:

```bash
python enteliweb-exporter.py config.ini --log-level DEBUG
```

## Metrics

The exporter exposes a single metric:

```
enteliweb_value{bacnet_id="<ref>", label="<name>"} <value>
```

- **`bacnet_id`** — the full BACnet object reference (e.g. `//site/10000.AI001`)
- **`label`** — the human-readable name from Enteliweb

The exporter expects a `?controller=` query parameter on `/metrics`. Without it, it returns a 400 error.

```bash
curl 'http://localhost:8085/metrics?controller=//site/10000'
```

A `/health` endpoint returns `200 OK` and can be used for liveness checks.

## Point Discovery

On first access to a controller, the exporter queries Enteliweb to discover all BACnet points (AI, AO, AV, BI, BO, CO). The discovered list is cached for `discovery_ttl` seconds, after which it is refreshed on the next scrape. Discovery is serialised so that concurrent scrapes of the same controller do not trigger duplicate API calls.

## Prometheus Configuration

Run a single exporter process per Enteliweb server and list all controllers as targets. Prometheus relabels them into the `?controller=` query parameter at scrape time.

See `prometheus.yml.example` for a full example:

```yaml
global:
  scrape_interval: 60s

scrape_configs:
  - job_name: 'enteliweb'
    scrape_timeout: 60s
    metrics_path: '/metrics'
    static_configs:
      - targets:
          - '//site/1000'
          - '//site/2000'
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_controller
      - target_label: __address__
        replacement: 'localhost:8085'
      - source_labels: [__param_controller]
        target_label: instance
```

How it works:

1. Each controller ref is listed as a `target` (e.g. `//site/1000`)
2. The first relabel rule copies `__address__` (the controller ref) into `__param_controller` — this becomes the `?controller=` query parameter
3. The second rule replaces `__address__` with the actual exporter address (`localhost:8085`)
4. The third rule sets the `instance` label to the controller ref so dashboards display it cleanly

Set `scrape_timeout` to at least `60s` — discovering and fetching points can take time on the first scrape.

## Fetching Controller Programs

The exporter can download all controller programs and save them to `controller_programs/`:

```bash
python enteliweb-exporter.py config.ini --get-programs //site/10000
```

This resolves the device, finds all `PG` objects, and writes each program to a text file. The exporter exits after saving.

## Architecture

One exporter process serves all controllers. Prometheus drives the scrape loop and passes the controller reference via the query parameter. The exporter handles login, CSRF tokens, session expiry, and point discovery transparently.
