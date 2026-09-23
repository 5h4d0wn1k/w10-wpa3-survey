> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# W10 — WPA3 / WPA2 Neighborhood Survey

Passive Wi-Fi security census tool — parses RSN Information Elements from WPA3/WPA2 beacon and
record data to classify security modes, report Protected Management Frame (PMF) adoption, resolve
vendor OUIs, and measure WPA3-transition coverage. Offline-first, standard library only.

![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/w10-wpa3-survey)
![GitHub last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/w10-wpa3-survey)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/w10-wpa3-survey)

## Why

WPA3 hardened the 4-way handshake, but only where it is actually deployed — and mixed
WPA2/WPA3-transition networks inherit the weaker mode. Measuring adoption starts by reading
beacons: the RSN Information Element encodes AKM suites (`0x0F:AC:02` PSK, `0x0F:AC:08` SAE) and PMF
capabilities. This tool decodes those bits byte-exactly, classifies APs into
Open/WEP/WPA2-Only/Transition/WPA3-Only, correlates vendor OUIs, and prints a census with PMF and
WPA3-coverage percentages. It is a passive wireless-security survey instrument for education —
survey only networks you own or hold written authorization to observe.

## Features

- **RSN capability parsing** — decodes AKM suites and pairwise/group ciphers from RSN IE data.
- **Five-category classification** — Open, WEP, WPA2-Only, WPA3-Transition, WPA3-Only.
- **PMF analysis** — distinguishes PMF-required (WPA3) from PMF-capable (WPA2) APs.
- **Vendor correlation** — 28-entry OUI database for common AP manufacturers.
- **SAE handshake bytes** — builds/parses auth commit and confirm frames for study (engine in
  `firmware/frame_core.py`).
- **Census statistics** — adoption ratios, percentage bars, and JSON report output.

## Quickstart

Prerequisite: Python 3.6+ (standard library; optional `scapy` for live capture, gracefully
degraded).

```bash
python3 firmware/wpa3_survey.py                         # offline demo with embedded AP records
python3 firmware/wpa3_survey.py --survey beacon --sae --json reports/w10.json
python3 -m unittest discover -s tests -v
```

Library use:

```python
from firmware.wpa3_survey import classify_ap, compute_census, lookup_vendor
classify_ap({"security_mode": "transition"})
```

## Project structure

- `firmware/wpa3_survey.py` — census engine and CLI.
- `firmware/frame_core.py` — byte-level beacon / SAE frame builder-parser.
- `tests/` — byte-exact unit tests (RSN/AKM parsing, SAE frames).

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep survey logic byte-exact and offline by default.

## License

MIT — see [LICENSE](LICENSE).