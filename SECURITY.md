# Security Policy

## Supported Versions

Security fixes are intended for the latest code on the `main` branch. Older revisions may not receive updates.

## Reporting a Vulnerability

Please do not publish credentials, private data, working exploit details, or sensitive target information in a public issue.

Use GitHub's private vulnerability reporting feature for this repository if it is enabled. Otherwise, contact the maintainer through the [GitHub profile](https://github.com/kaandgnsh) and include a concise description, affected version or commit, impact, and safe reproduction steps.

Please share only the minimum information needed to reproduce the issue. Allow time for triage and a fix before publicly disclosing details.

## Network Security Boundary

For direct HTTP(S) requests, ARGUS validates a URL and pins each new TCP connection to a numeric address resolved and checked immediately before connecting. This prevents the socket from performing a second hostname lookup after validation. The original hostname is retained for the HTTP Host header and TLS certificate/SNI checks. Response bodies are limited to 10 MiB by default; explicitly passing `max_bytes=None` disables this size cap and should be reserved for trusted content.

Configured HTTP, SOCKS, or Tor proxies are a separate trust boundary. A remote-DNS proxy may resolve the destination outside ARGUS, so local DNS pinning cannot guarantee which address the proxy connects to. Use only a proxy you trust and understand. The explicit `allow_private=True` option opts out of URL validation and direct DNS pinning; reserve it for controlled environments.

## Data Handling

ARGUS may store locally collected identifiers, entities, relationships, reports, logs, and caches. Some modules may send queries to configured third-party providers. Treat generated artifacts and provider credentials as sensitive, and review them before sharing.
