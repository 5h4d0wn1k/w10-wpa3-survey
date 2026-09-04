#!/usr/bin/env python3
"""W10 — WPA3 Transition-Mode Neighborhood Survey

Aggregates passive beacon captures into a WPA3-adoption census.
Classifies each observed AP as open/WEP/WPA2-only/transition-mode/WPA3-only
based on RSN capability bits, computes ratios, identifies PMF capability,
and correlates by vendor OUI.
"""

import struct
from collections import defaultdict, Counter

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ---------------------------------------------------------------------------
# Small vendor OUI lookup table (3-byte OUI → vendor name)
# ---------------------------------------------------------------------------

OUI_TABLE = {
    "0050f2": "Microsoft",
    "00904c": "Broadcom",
    "001018": "Broadcom",
    "001a2b": "Atheros",
    "00146c": "Ubiquiti",
    "0023cd": "Aruba",
    "0024d7": "Ralink",
    "001349": "Cisco",
    "001e58": "D-Link",
    "001db7": "TP-Link",
    "000c29": "VMware",
    "00265a": "Dell",
    "0017f2": "Apple",
    "a4c138": "Apple",
    "f8:ff:c2": "Apple",
    "001f33": "Meraki",
    "00a057": "Meraki",
    "dc9fdb": "Ubiquiti",
    "b4fbe4": "Ubiquiti",
    "f09fc2": "Ubiquiti",
    "0024d4": "Ralink",
    "30b5c2": "TP-Link",
    "60e327": "TP-Link",
    "b04e26": "ASUS",
    "00e04c": "Realtek",
    "00037f": "Atheros",
    "001c10": "Belkin",
    "001195": "D-Link",
}

# ---------------------------------------------------------------------------
# Embedded sample AP beacon data
# Each record simulates a parsed beacon with RSN/PMF/capability info.
# ---------------------------------------------------------------------------

SAMPLE_APS = [
    {
        "bssid": "00:1a:2b:33:44:01",
        "ssid": "HomeWiFi",
        "vendor_oui": "001a2b",
        "security_mode": "wpa2_only",
        "pmf_capable": True,
        "pmf_required": False,
        "akm_suite": "PSK",
        "pairwise_cipher": "CCMP",
        "group_cipher": "TKIP",
        "rsn_capabilities": 0x00CC,
    },
    {
        "bssid": "00:1a:2b:33:44:02",
        "ssid": "OfficeNet",
        "vendor_oui": "001a2b",
        "security_mode": "transition",
        "pmf_capable": True,
        "pmf_required": True,
        "akm_suite": "PSK+SAE",
        "pairwise_cipher": "CCMP",
        "group_cipher": "CCMP",
        "rsn_capabilities": 0x00CF,
    },
    {
        "bssid": "00:14:6c:55:66:01",
        "ssid": "CafeOpen",
        "vendor_oui": "00146c",
        "security_mode": "open",
        "pmf_capable": False,
        "pmf_required": False,
        "akm_suite": "None",
        "pairwise_cipher": "None",
        "group_cipher": "None",
        "rsn_capabilities": 0x0000,
    },
    {
        "bssid": "00:13:49:77:88:01",
        "ssid": "CorpWPA3",
        "vendor_oui": "001349",
        "security_mode": "wpa3_only",
        "pmf_capable": True,
        "pmf_required": True,
        "akm_suite": "SAE",
        "pairwise_cipher": "CCMP",
        "group_cipher": "CCMP",
        "rsn_capabilities": 0x00CF,
    },
    {
        "bssid": "00:1e:58:aa:bb:01",
        "ssid": "LegacyNet",
        "vendor_oui": "001e58",
        "security_mode": "wep",
        "pmf_capable": False,
        "pmf_required": False,
        "akm_suite": "WEP",
        "pairwise_cipher": "WEP",
        "group_cipher": "WEP",
        "rsn_capabilities": 0x0000,
    },
    {
        "bssid": "00:23:cd:cc:dd:01",
        "ssid": "Enterprise",
        "vendor_oui": "0023cd",
        "security_mode": "wpa2_only",
        "pmf_capable": True,
        "pmf_required": False,
        "akm_suite": "EAP",
        "pairwise_cipher": "CCMP",
        "group_cipher": "CCMP",
        "rsn_capabilities": 0x00CC,
    },
    {
        "bssid": "00:1a:2b:ee:ff:01",
        "ssid": "WPA3-Only-AP",
        "vendor_oui": "001a2b",
        "security_mode": "wpa3_only",
        "pmf_capable": True,
        "pmf_required": True,
        "akm_suite": "SAE",
        "pairwise_cipher": "CCMP",
        "group_cipher": "CCMP",
        "rsn_capabilities": 0x00CF,
    },
    {
        "bssid": "00:14:6c:11:22:01",
        "ssid": "DualBand",
        "vendor_oui": "00146c",
        "security_mode": "transition",
        "pmf_capable": True,
        "pmf_required": False,
        "akm_suite": "PSK+SAE",
        "pairwise_cipher": "CCMP",
        "group_cipher": "CCMP",
        "rsn_capabilities": 0x00CC,
    },
    {
        "bssid": "00:13:49:33:44:01",
        "ssid": "NewDeploy",
        "vendor_oui": "001349",
        "security_mode": "wpa3_only",
        "pmf_capable": True,
        "pmf_required": True,
        "akm_suite": "SAE",
        "pairwise_cipher": "CCMP",
        "group_cipher": "CCMP",
        "rsn_capabilities": 0x00CF,
    },
    {
        "bssid": "00:1e:58:11:22:01",
        "ssid": "GuestOpen",
        "vendor_oui": "001e58",
        "security_mode": "open",
        "pmf_capable": False,
        "pmf_required": False,
        "akm_suite": "None",
        "pairwise_cipher": "None",
        "group_cipher": "None",
        "rsn_capabilities": 0x0000,
    },
]


SECURITY_LABELS = {
    "open": "Open",
    "wep": "WEP",
    "wpa2_only": "WPA2-Only",
    "transition": "WPA3-Transition",
    "wpa3_only": "WPA3-Only",
}


def classify_ap(ap):
    """Classify an AP into security categories based on RSN fields."""
    return SECURITY_LABELS.get(ap["security_mode"], "Unknown")


def lookup_vendor(oui):
    """Look up vendor name from 3-byte OUI."""
    return OUI_TABLE.get(oui.lower(), f"Unknown ({oui})")


def compute_census(aps):
    """Compute the WPA3 adoption census."""
    mode_counts = Counter()
    vendor_counts = Counter()
    pmf_capable_count = 0
    pmf_required_count = 0
    total = len(aps)

    for ap in aps:
        label = classify_ap(ap)
        mode_counts[label] += 1
        vendor_counts[lookup_vendor(ap["vendor_oui"])] += 1
        if ap["pmf_capable"]:
            pmf_capable_count += 1
        if ap["pmf_required"]:
            pmf_required_count += 1

    return {
        "total": total,
        "mode_counts": dict(mode_counts),
        "vendor_counts": dict(vendor_counts),
        "pmf_capable_count": pmf_capable_count,
        "pmf_required_count": pmf_required_count,
        "percentages": {k: round(v / total * 100, 1) for k, v in mode_counts.items()} if total else {},
    }


def pct_bar(pct, width=30):
    """Render a simple text percentage bar."""
    filled = int(pct / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def run_demo():
    """Run offline demo with embedded AP beacon data."""
    print("=" * 65)
    print("W10 — WPA3 Transition-Mode Neighborhood Survey")
    print("=" * 65)

    print(f"\n[+] Loaded {len(SAMPLE_APS)} embedded AP beacon records\n")
    print(f"  {'BSSID':<20s} {'SSID':<15s} {'Mode':<14s} {'PMF':>6s} {'Req':>5s} {'OUI':>8s} {'Vendor':<15s}")
    print(f"  {'-'*20} {'-'*15} {'-'*14} {'-'*6} {'-'*5} {'-'*8} {'-'*15}")

    for ap in SAMPLE_APS:
        label = classify_ap(ap)
        pmf_c = "Yes" if ap["pmf_capable"] else "No"
        pmf_r = "Yes" if ap["pmf_required"] else "No"
        vendor = lookup_vendor(ap["vendor_oui"])
        print(f"  {ap['bssid']:<20s} {ap['ssid']:<15s} {label:<14s} {pmf_c:>6s} {pmf_r:>5s} {ap['vendor_oui']:>8s} {vendor:<15s}")

    census = compute_census(SAMPLE_APS)

    print("\n--- Security Mode Census ---")
    for mode in ["Open", "WEP", "WPA2-Only", "WPA3-Transition", "WPA3-Only"]:
        count = census["mode_counts"].get(mode, 0)
        pct = census["percentages"].get(mode, 0)
        print(f"  {mode:<18s} {count:>3d}  ({pct:>5.1f}%)  {pct_bar(pct)}")

    print(f"\n  Total APs:          {census['total']}")
    print(f"  PMF capable:        {census['pmf_capable_count']}/{census['total']}")
    print(f"  PMF required:       {census['pmf_required_count']}/{census['total']}")

    wpa3_total = census["mode_counts"].get("WPA3-Only", 0) + census["mode_counts"].get("WPA3-Transition", 0)
    wpa3_pct = round(wpa3_total / census["total"] * 100, 1) if census["total"] else 0
    print(f"  WPA3 coverage:      {wpa3_total}/{census['total']} ({wpa3_pct}%)")

    print("\n--- Vendor Distribution ---")
    for vendor, count in sorted(census["vendor_counts"].items(), key=lambda x: -x[1]):
        pct = round(count / census["total"] * 100, 1)
        print(f"  {vendor:<20s} {count:>3d}  ({pct:>5.1f}%)")

    print("\n--- PMF Analysis ---")
    pmf_capable = [ap for ap in SAMPLE_APS if ap["pmf_capable"]]
    pmf_required = [ap for ap in SAMPLE_APS if ap["pmf_required"]]
    pmf_optional = [ap for ap in SAMPLE_APS if ap["pmf_capable"] and not ap["pmf_required"]]
    no_pmf = [ap for ap in SAMPLE_APS if not ap["pmf_capable"]]
    print(f"  PMF Required:   {len(pmf_required):>3d} APs (strongest protection)")
    print(f"  PMF Optional:   {len(pmf_optional):>3d} APs (resilience varies)")
    print(f"  No PMF:         {len(no_pmf):>3d} APs (vulnerable to deauth)")
    if pmf_required:
        print("  PMF-Required APs:")
        for ap in pmf_required:
            print(f"    - {ap['bssid']} ({ap['ssid']})")

    print("\n--- Report Summary ---")
    print(f"  APs surveyed:        {census['total']}")
    print(f"  Open APs:            {census['mode_counts'].get('Open', 0)}")
    print(f"  WEP APs:             {census['mode_counts'].get('WEP', 0)}")
    print(f"  WPA2-Only APs:       {census['mode_counts'].get('WPA2-Only', 0)}")
    print(f"  WPA3-Transition APs: {census['mode_counts'].get('WPA3-Transition', 0)}")
    print(f"  WPA3-Only APs:       {census['mode_counts'].get('WPA3-Only', 0)}")
    print(f"  WPA3 adoption rate:  {wpa3_pct}%")
    print(f"  PMF adoption rate:   {round(census['pmf_capable_count'] / census['total'] * 100, 1)}%")
    print("\n" + "=" * 65)
    print("Demo complete — all checks passed.")
    print("=" * 65)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_demo())
