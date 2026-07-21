<div align="center">

# jenknums

A read-only Jenkins enumerator with CVE correlation and raw collection.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/pajarori/jenknums?style=flat&logo=github)](https://github.com/pajarori/jenknums/stargazers)
[![Forks](https://img.shields.io/github/forks/pajarori/jenknums?style=flat&logo=github)](https://github.com/pajarori/jenknums/network/members)
[![Issues](https://img.shields.io/github/issues/pajarori/jenknums?style=flat&logo=github)](https://github.com/pajarori/jenknums/issues)
[![Last Commit](https://img.shields.io/github/last-commit/pajarori/jenknums?style=flat&logo=github)](https://github.com/pajarori/jenknums/commits/main)

</div>

## Installation

```bash
pipx install git+https://github.com/pajarori/jenknums.git
```

To upgrade an existing installation:

```bash
pipx upgrade jenknums
```

## Usage

```bash
# Scan a Jenkins target
jenknums -u https://jenkins.example.com

# Scan a Jenkins context path
jenknums -u https://example.com/jenkins

# Run additional read-only checks
jenknums -u https://jenkins.example.com --verify

# Authenticate with an API token
jenknums -u https://jenkins.example.com --user admin --token-file token.txt

# Save output
jenknums -u https://jenkins.example.com -o results.json

# JSON stdout
jenknums -u https://jenkins.example.com --json

# Limit collection for large Jenkins instances
jenknums -u https://jenkins.example.com --max-builds 5 --no-console --no-workspace-index
```

### Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Jenkins URL to scan |
| `-o, --output` | Summary report (`.json`, `.csv`, `.txt`) |
| `--dump-dir` | Raw collection directory |
| `--request-concurrency` | Concurrent requests (default: 6) |
| `-s, --sleep` | Delay between requests in seconds |
| `--user` | Jenkins username |
| `--token`, `--token-file` | Jenkins API token source |
| `--cookie`, `--cookie-file` | Jenkins session Cookie header source |
| `--verify` | Additional safe, read-only checks |
| `--display-limit` | Maximum entries shown per terminal section (default: 10) |
| `--max-builds` | Limit builds collected per job |
| `--no-console` | Skip full console log collection |
| `--no-workspace-index` | Skip recursive workspace indexing |
| `-k, --insecure` | Disable TLS certificate validation |
| `--offline` | Use the bundled vulnerability database |
| `--update-db` | Update the vulnerability database and exit |
| `--no-retry` | Disable request retries |
| `--json` | Output JSON to stdout |

## Checks

- Jenkins version, views, jobs, plugins, nodes, users, and exposed metadata
- Anonymous access, CLI, agent listener, instance identity, and plugin endpoints
- Job, view, node, build, console, workspace, and system information when readable
- Jenkins core and plugin versions against official security advisories

Raw responses are saved to `jenknums-output/<timestamp>/`. Plugin versions are only shown when Jenkins exposes them; passive detections are marked as inferred.

`jenknums` only uses `GET`, `HEAD`, `OPTIONS`, and a safe WebSocket handshake. It does not trigger builds or send exploit payloads.

## Credits & References

- [Jenkins Security Advisories](https://www.jenkins.io/security/advisories/)
- [Jenkins Update Center](https://updates.jenkins.io/)
- [Jenkins Remote Access API](https://www.jenkins.io/doc/book/using/remote-access-api/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)

## License

MIT License
