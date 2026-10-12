# ARGUS

<p align="center">
  <strong>A modular OSINT and reconnaissance framework for public-source research, entity correlation, and local reporting.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-444444?style=for-the-badge" alt="Supported platforms">
  <img src="https://img.shields.io/badge/License-MIT-315C45?style=for-the-badge" alt="MIT license">
  <a href="https://github.com/kaandgnsh/Argus/actions/workflows/tests.yml">
    <img src="https://github.com/kaandgnsh/Argus/actions/workflows/tests.yml/badge.svg?branch=main" alt="Tests">
  </a>
</p>

---

## Overview

**ARGUS** collects information from public sources, records entities and relationships in a local SQLite database, and exports findings to structured reports. Its provider-based architecture supports domain, IP, URL, username, email, phone-number, GitHub, threat-indicator, and local-file workflows.

ARGUS is an educational software and security-research project. It is not a guarantee that a result is correct, complete, current, or legally appropriate to collect.

> [!WARNING]
> **Use responsibly.** Run ARGUS only on your own data, in a controlled lab, or against targets for which you have explicit authorization. Phone numbers, email addresses, usernames, IP addresses, and related identifiers may be sent to third-party providers. Public availability does not grant unlimited permission to collect, correlate, or republish information. Do not use ARGUS for stalking, harassment, unauthorized access, or evasion of security controls.

## Features

- **Multiple target types:** usernames, email addresses, phone numbers, domains/DNS, IP addresses, URLs, hashes, GitHub profiles, threat indicators, and local files.
- **Provider-based architecture:** modular DNS, RDAP, Certificate Transparency, and threat-intelligence lookups.
- **Local database:** entities, relationships, evidence, and cases are stored in SQLite.
- **Report exports:** JSON, HTML, CSV, Markdown, and GraphViz DOT.
- **File analysis:** hash calculation, IOC extraction, archive inspection, and optional EXIF/PDF/media metadata support.
- **Security controls:** URL and redirect checks for HTTP requests, archive member/size/path limits, and bounded subprocess operations for supported external tools.
- **Optional external tools:** list supported tools and request installation explicitly.
- **No automatic dependency installation at startup:** install Python dependencies deliberately and add optional components only when you need them.

## Requirements

- Python 3.10 or newer
- Git
- Required Python packages listed in `requirements.txt`

## Installation

### Linux, macOS, and Termux

Clone the repository:

```bash
git clone https://github.com/kaandgnsh/Argus.git
cd Argus
```

Recommended: create an isolated virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python argus.py --version
```

If your Linux distribution does not have the `venv` module installed, install the matching OS package (often named `python3-venv`) and repeat the commands. On Termux, first run:

```bash
pkg update
pkg install python git
```

### Windows (PowerShell)

```powershell
git clone https://github.com/kaandgnsh/Argus.git
cd Argus

py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python argus.py --version
```

### Installation helper

On POSIX-compatible systems, the helper creates a local `.venv`, installs required packages there, and asks before installing the optional dependency set:

```bash
sh install.sh
```

Review the prompts before accepting optional dependencies. The helper does not install OS-level external tools.

### Optional dependencies

Only install the optional packages needed for your workflow:

```bash
python -m pip install -r requirements-optional.txt
```

Some packages also need OS libraries. For example, `python-magic` may require the system's `libmagic` library. Optional phone-number integrations can send identifiers to third-party providers, so review provider behavior and privacy policies before enabling them.

For development and tests:

```bash
python -m pip install -r requirements-dev.txt
```

## Quick Start

Start the interactive menu:

```bash
python3 argus.py
```

Examples of supported workflows:

```bash
# Domain, DNS, and IP information
python3 argus.py -domain example.com
python3 argus.py -dns example.com
python3 argus.py -ip 8.8.8.8 --no-map

# Username, email, and public GitHub profile lookups
python3 argus.py -username kaandgnsh
python3 argus.py -email user@example.com
python3 argus.py -github torvalds

# URL, hash, and threat-indicator lookups
python3 argus.py -url https://example.com
python3 argus.py -hash 5d41402abc4b2a76b9719d911017c592
python3 argus.py -threat 8.8.8.8

# Local file metadata and search
python3 argus.py -file ./document.pdf
python3 argus.py -exif ./photo.jpg
python3 argus.py -search "site:example.com security.txt"

# Export records already stored in the local database
python3 argus.py --export-all
```

**Important:** `--export-all` does not start a new scan; it exports records already collected in the SQLite database. Search, phone-number, IP, and provider-based commands may send requests to third-party services.

## CLI Reference

| Option | Description |
|:--|:--|
| `-phone NUMBER` | Phone-number analysis; may use configured third-party providers. |
| `-username USER`, `-u USER` | Username research across supported platforms. |
| `-email EMAIL` | Email-related intelligence. |
| `-domain DOMAIN` | Domain intelligence and subdomain information. |
| `-dns DOMAIN` | DNS-focused domain lookup. |
| `-ip IP` | IP intelligence; use `--no-map` to hide the ASCII map. |
| `-url URL` | URL, HTTP-header, and redirect analysis. |
| `-hash HASH` | Hash identification and related lookup. |
| `-github USER` | Public GitHub profile and repository information. |
| `-threat IOC` | Look up a supported IP, domain, URL, hash, or CVE indicator. |
| `-file PATH` | Analyze a local file and extract supported indicators. |
| `-exif IMAGE` | Extract image metadata; `--save-thumb` saves an embedded thumbnail under `reports/`. |
| `-dork QUERY` | Submit a search-engine query. |
| `-search QUERY` | Perform a general web search. |
| `-correlate QUERY` | Explore relationships recorded in the local database. |
| `--export-json` | Export a JSON report. |
| `--export-html` | Export an HTML report. |
| `--export-csv` | Export entity and relationship CSV files. |
| `--export-md` | Export a Markdown report. |
| `--export-dot` | Export a GraphViz DOT relationship graph. |
| `--export-all` | Generate all supported report formats. |
| `--list-tools` | Show supported external tools and their status. |
| `--install-tools TOOL` | Request installation of a selected external tool. Use `all` to list tools. |
| `--no-color` | Disable colored terminal output. |
| `--debug` | Enable debug logging. |
| `--clear-cache` | Clear the local cache. |
| `--json` | Enable JSON stdout output for supported `-search` and `-exif` workflows. |
| `--subdomain-log PATH` | Write the complete subdomain list to a file. |
| `--no-map` | Hide the ASCII map in IP lookups. |
| `--save-thumb` | Save an embedded image thumbnail under `reports/`. |
| `--version` | Print the installed ARGUS version. |

To inspect the available external tools:

```bash
python3 argus.py --list-tools
```

Read the command shown by ARGUS before approving any external-tool installation.

## Privacy and Security

- **Third-party lookups:** the enabled provider configuration determines which external services receive a query. Check their retention policies and terms before submitting personal identifiers.
- **Provider configuration:** review `config/providers.json` and disable providers you do not need. Do not commit API keys or private provider configuration to Git; use the environment variables expected by each provider.
- **Local artifacts:** entities and relationships may be stored in `data/argus.sqlite`; reports, logs, and caches may include sensitive findings. Keep local data directories private and inspect reports before sharing them.
- **HTTP safeguards:** ARGUS checks URLs and redirect targets, but network-level behavior can be complex. Treat these checks as defense in depth, not as a proof that every endpoint or DNS configuration is safe.
- **File analysis:** analyze only files you are authorized to inspect. Avoid sharing reports containing personal information, tokens, private paths, or internal network details.
- **Result quality:** automated matches can be false positives or stale. Verify material findings against the original source before relying on them.

## Tests

Install development dependencies and run the test suite:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

GitHub Actions runs tests on Python 3.10, 3.11, and 3.12. The suite covers HTTP and URL safeguards, security helpers, phone-number normalization, CLI behavior, and report exports.

## Project Structure

```text
Argus/
├── argus.py
├── install.sh
├── requirements.txt
├── requirements-optional.txt
├── requirements-dev.txt
├── config/
├── core/
├── data/
├── cache/
├── logs/
├── modules/
├── providers/
├── reports/
└── tests/
```

## Contributing

1. Fork the repository.
2. Create a focused branch, for example `git checkout -b fix/short-description`.
3. Document behavioral changes and add tests where appropriate.
4. Run `python -m pytest -q`.
5. Open a pull request with a concise explanation of the change.

Please review the security policy in [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

ARGUS is released under the [MIT License](LICENSE).

## Author

**Kaan DOĞAN** · [GitHub](https://github.com/kaandgnsh) · [LinkedIn](https://www.linkedin.com/in/kaan-do%C4%9Fan-911663280/) · [Instagram](https://instagram.com/kaandgn.sh)
