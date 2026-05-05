# Agent/API Traffic Detector

A specialized detector for agent and API traffic extracted from `network-anomaly-monitor`.

## Features

- Detects known AI/agent protocol ports
- Inspects payloads for agent-specific signatures
- Monitors DNS traffic for AI service domains
- Supports quiet and no-log modes

## Usage

```bash
python main.py --interface eth0 --quiet
```

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the `LICENSE` file for details.
