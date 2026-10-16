# PortLens

A fast, lightweight, multithreaded TCP port scanner written in pure Python. PortLens finds open ports on a host, labels common services, optionally grabs service banners, and exports results to JSON.

> **Legal notice:** Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal and may violate network policies. You are responsible for how you use this tool.

## Features

- Multithreaded TCP connect scanning
- Flexible port input: single ports, lists, and ranges (`22,80,443`, `1-1024`)
- Common service name detection (ssh, http, mysql, rdp, and more)
- Optional banner grabbing (`--banner`)
- JSON export for reports and automation
- Zero third-party dependencies

## Requirements

- Python 3.9 or newer
- Works on Linux, macOS, and Windows

## Installation

### Linux / macOS

```bash
# 1. Clone the repository (replace with your own repo URL)
git clone https://github.com/<your-username>/portlens.git
cd portlens

# 2. (Optional) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies (none required, but this keeps setup consistent)
pip install -r requirements.txt

# 4. Verify the install
python3 portlens.py --help
```

### Windows (PowerShell)

```powershell
# 1. Clone the repository (replace with your own repo URL)
git clone https://github.com/<your-username>/portlens.git
cd portlens

# 2. (Optional) Create and activate a virtual environment
python -m venv venv
venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify the install
python portlens.py --help
```

### Without Git

Download `portlens.py` directly and run it. No installation is needed.

## Usage

```bash
python portlens.py <target> [options]
```

| Option | Description | Default |
|---|---|---|
| `-p`, `--ports` | Ports to scan, e.g. `80,443` or `1-1024` | `1-1024` |
| `-t`, `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Per-port timeout in seconds | `1.0` |
| `--banner` | Try to grab service banners | off |
| `-o`, `--output` | Save results to a JSON file | none |

### Examples

```bash
# Scan the default port range on localhost
python portlens.py 127.0.0.1

# Scan specific ports with banner grabbing
python portlens.py 192.168.1.10 -p 22,80,443 --banner

# Full port scan, faster settings, saved to JSON
python portlens.py 192.168.1.10 -p 1-65535 -t 200 --timeout 0.5 -o results.json
```

For safe practice, scan `127.0.0.1`, a device on your own network, or `scanme.nmap.org` (provided by the Nmap project for light test scans).

### Sample output

```
Scanning 192.168.1.10 (192.168.1.10) - 1024 ports
Started: 2026-10-16 14:30:00

PORT    SERVICE       BANNER
22      ssh           SSH-2.0-OpenSSH_9.6
80      http
443     https

3 open port(s) found.
```

### JSON output format

```json
{
  "target": "192.168.1.10",
  "ip": "192.168.1.10",
  "scanned_at": "2026-10-16T14:30:00",
  "open_ports": [
    { "port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.6" }
  ]
}
```

## Limitations

- TCP connect scans only (no UDP or SYN/stealth scanning)
- IPv4 only
- Full connections are easy for firewalls and intrusion detection systems to log

## Roadmap

- [ ] UDP scanning
- [ ] Subnet host discovery
- [ ] Scan diffing to alert on newly opened ports
- [ ] IPv6 support

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

Released under the [MIT License](LICENSE).
