# W10 — WPA3 Transition-Mode Neighborhood Survey `w10-wpa3-survey`

Passive beacon census tool for WPA3 adoption measurement and PMF deployment analysis.

## Overview

This project implements a passive WPA3-adoption survey from beacon captures:
- **Security mode classification**: Classifies APs as Open/WEP/WPA2-Only/Transition-Mode/WPA3-Only from RSN capability bits
- **RSN capability parsing**: Decodes RSN Information Element fields for accurate security posture detection
- **PMF analysis**: Identifies PMF-capable vs PMF-required APs with resilience implications
- **Vendor correlation**: Maps vendor OUIs to manufacturer names for deployment-pattern analysis
- **Census statistics**: Computes adoption ratios, percentage bars, and deployment summaries
- **Offline-first**: Runs on embedded AP beacon data with no network dependency

## Features

- **RSN capability bit parser**: Decodes AKM suites, pairwise/group ciphers from RSN IE data
- **5-category classification**: Open, WEP, WPA2-Only, WPA3-Transition, WPA3-Only
- **PMF Required vs Capable**: Differentiates mandatory PMF (WPA3) from optional PMF (WPA2)
- **OUI vendor lookup**: 28-entry vendor database for common AP manufacturers
- **Percentage bar visualization**: Text-based progress bars for census categories
- **Vendor distribution**: Manufacturer breakdown for deployment-pattern insights
- **PMF resilience scoring**: Reports PMF adoption rates across the surveyed neighborhood
- **Offline demo**: 10 embedded AP records covering all 5 security categories

## Installation

```bash
# No external dependencies — Python 3.6+ standard library only
# Optional: scapy for live beacon capture (gracefully degraded if absent)
python3 firmware/wpa3_survey.py
```

## Usage

```bash
# Run offline demo with embedded AP data
python3 firmware/wpa3_survey.py
```

```python
from firmware.wpa3_survey import classify_ap, compute_census, lookup_vendor

# Classify a single AP
label = classify_ap({"security_mode": "transition"})

# Compute full census from list of APs
census = compute_census(ap_list)

# Look up vendor from OUI
vendor = lookup_vendor("001a2b")
```

## Example Output

```
=================================================================
W10 — WPA3 Transition-Mode Neighborhood Survey
=================================================================

[+] Loaded 10 embedded AP beacon records

  BSSID               SSID            Mode           PMF   Req       OUI Vendor
  ------------------- --------------- -------------- ------ ----- -------- ---------------
  00:1a:2b:33:44:01   HomeWiFi        WPA2-Only         Yes    No   001a2b Atheros
  00:1a:2b:33:44:02   OfficeNet       WPA3-Transition   Yes   Yes   001a2b Atheros
  ...

--- Security Mode Census ---
  Open                 2  ( 20.0%)  [######------------------------]
  WEP                  1  ( 10.0%)  [###---------------------------]
  WPA2-Only            2  ( 20.0%)  [######------------------------]
  WPA3-Transition      2  ( 20.0%)  [######------------------------]
  WPA3-Only            3  ( 30.0%)  [#########---------------------]

  PMF capable:        7/10
  PMF required:       5/10
  WPA3 coverage:      5/10 (50.0%)

--- Vendor Distribution ---
  Atheros              4  ( 40.0%)
  Ubiquiti             2  ( 20.0%)
  Cisco                1  ( 10.0%)
  ...

--- PMF Analysis ---
  PMF Required:     5 APs (strongest protection)
  PMF Optional:     2 APs (resilience varies)
  No PMF:           3 APs (vulnerable to deauth)

--- Report Summary ---
  WPA3 adoption rate:  50.0%
  PMF adoption rate:   70.0%
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission before performing passive wireless surveys on networks you do not own
- Beacon capture and analysis on third-party networks may be subject to local regulations
- This tool should ONLY be used on networks you own or have written authorization to survey

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized interception of network management frames may constitute illegal access under some interpretations
- **Federal Communications Act (47 U.S.C. § 333)**: Passive monitoring is generally permitted but interfering with or responding to beacons is prohibited
- **Wiretap Act (18 U.S.C. § 2511)**: Passively receiving broadcast beacon frames is typically lawful as they are intentionally broadcast, but analysis for tracking may have privacy implications
- **State Laws**: Many states have additional wireless surveillance and computer crime statutes

### Acceptable Use
- Surveying WPA3 adoption on your own wireless infrastructure
- Authorized penetration testing with written scope
- Academic research on wireless security adoption
- Privacy-focused wireless security education

### Prohibited Use
- Surveilling third-party networks for tracking or intelligence purposes
- Using beacon data to identify and target specific users or organizations
- Any activity that violates applicable laws or regulations
- Operating an intentional radiator outside FCC/regulatory limits

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## Live Lab Test Plan

This repo is a byte-level census + SAE handshake *engineering* tool: beacons and SAE
auth commit/confirm frames are built/parsed offscreen — no capture, no radio.

Offline (this repo, no radio):
1. `python3 firmware/wpa3_survey.py --survey beacon --sae --json reports/w10.json` — classify
   APs from the RSN IE in byte-level beacons, print the WPA3-adoption census and the SAE
   commit/confirm byte sequence (exit 0).
2. `python3 -m unittest discover -s tests` — byte-exact tests (RSN/AKM parsing, SAE frames) pass.

Authorized lab (only with written scope + shield + authorized channel):
3. Point a monitor at your lab AP and confirm the beacon's RSNIE AKM bits match what the
   byte parser reports (PSK=0x0f/ac/02, SAE=0x0f/ac/08).
4. `green = permitted`: any real-air run requires written lab authorization, a shielded bench,
   and an authorized channel; never survey networks you don't own or lack scope for.

## Metrics

- Frame type engineered byte-exact: beacon with RSN IE (element 48) for PSK/SAE/PSK+SAE
- RSN parser: AKM suite identifiers decoded straight off the IE (0x0F:AC:02 PSK, 0x0F:AC:08 SAE)
- SAE handshake bytes: auth commit (alg 3, tx 1) + auth confirm (tx 2), STA and AP sides
- Census: WPA2-Only / WPA3-Transition / WPA3-Only / Open + PMF capability, vendor OUI
- Coverage: 8-AP record corpus (census) + 6 beacon-representable (RSN AKM)

- Test suite: `python3 -m unittest discover -s tests`
- Reports: `reports/` (gitignored)

## License

MIT
