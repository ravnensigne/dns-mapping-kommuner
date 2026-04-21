# dns-mapping

Mapping mail server dependencies for Danish municipalities using DNS data.

This fork focuses on municipality domains. The `domains.csv` file in this repository contains municipality domains that can be analyzed with the script.

## Prerequisites

- **Python**: 3.13
- **uv** (package/dependency manager): install via:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Quick start

1. Ensure `domains.csv` is placed in the project root. The current dataset contains municipality domains and uses this schema:

```csv
domain
aarhus.dk
aalborg.dk
```

2. Run the program using uv (no virtualenv activation needed):

```bash
uv run main.py
```

This will resolve DNS records for each domain and produce:

- `domain_dns_results.csv`
- `analysis_results.csv`

The script also prints overall summary tables to `stdout`.

## Notes on dependencies

Dependencies are defined in `pyproject.toml` and locked in `uv.lock`. You generally do not need to run anything besides `uv run ...`, but if you want to pre-sync the environment:

```bash
uv sync
```

## What the script does

For each domain in `domains.csv`, the script:

- Queries `MX`, `TXT` (SPF includes and ip4s), `A` (and looks up ASN country), and some common DKIM selector `CNAME`s
- Looks up `autodiscover.<domain>` `CNAME`
- Writes normalized data to `domain_dns_results.csv`
- Computes Microsoft 365 indicator columns and writes a full table to `analysis_results.csv`
- Prints overall summaries across the municipality domains in the input file

## Input schema

- **domain**: the municipality domain to analyze (e.g., `aarhus.dk`)

## Output files

- `domain_dns_results.csv`: raw/normalized DNS lookups including SPF, DKIM, autodiscover, and derived `domain_countries`.
- `analysis_results.csv`: includes Microsoft-related indicator columns and summary-friendly fields.
