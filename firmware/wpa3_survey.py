#!/usr/bin/env python3
"""W10 — WPA3 Transition-Mode Neighborhood Survey & SAE Handshake Engineering.

Two capabilities, both offline (pure-stdlib bytes):

  1. WPA3-adoption census from *byte-level beacon frames* (RSN IE / AKM suite
     parsed directly off the wire format).
  2. WPA3 SAE (Dragonfly) handshake *byte-sequence engineering*: the auth
     commit/confirm frames a transition-mode or SAE-only AP exchange, built and
     printed offscreen — no radio emitted.

The original record-based census (OUI/PMF/vendor analysis) is preserved.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from collections import Counter, defaultdict

try:
    from firmware import frame_core as fc
except ImportError:
    try:
        import frame_core as fc
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "firmware"))
        import frame_core as fc

# ----------------------------------------------------------------------
# OUI table + record census (preserved from original)
# ----------------------------------------------------------------------

OUI_TABLE = {
    "0050f2": "Microsoft", "00904c": "Broadcom", "001018": "Broadcom",
    "001a2b": "Atheros", "00146c": "Ubiquiti", "0023cd": "Aruba",
    "0024d7": "Ralink", "001349": "Cisco", "001e58": "D-Link",
    "001db7": "TP-Link", "000c29": "VMware", "00265a": "Dell",
    "0017f2": "Apple", "a4c138": "Apple", "001f33": "Meraki",
    "00a057": "Meraki", "dc9fdb": "Ubiquiti", "b4fbe4": "Ubiquiti",
    "f09fc2": "Ubiquiti", "0024d4": "Ralink", "30b5c2": "TP-Link",
    "60e327": "TP-Link", "b04e26": "ASUS", "00e04c": "Realtek",
    "00037f": "Atheros", "001c10": "Belkin", "001195": "D-Link",
}

SAMPLE_APS = [
    {"bssid": "00:1a:2b:33:44:01", "ssid": "lab-homewifi", "vendor_oui": "001a2b",
     "security_mode": "wpa2_only", "pmf_capable": True, "pmf_required": False,
     "akm_suite": "PSK", "pairwise_cipher": "CCMP", "group_cipher": "TKIP",
     "rsn_capabilities": 0x00CC},
    {"bssid": "00:1a:2b:33:44:02", "ssid": "lab-officenet", "vendor_oui": "001a2b",
     "security_mode": "transition", "pmf_capable": True, "pmf_required": True,
     "akm_suite": "PSK+SAE", "pairwise_cipher": "CCMP", "group_cipher": "CCMP",
     "rsn_capabilities": 0x00CF},
    {"bssid": "00:14:6c:55:66:01", "ssid": "lab-cafeopen", "vendor_oui": "00146c",
     "security_mode": "open", "pmf_capable": False, "pmf_required": False,
     "akm_suite": "None", "pairwise_cipher": "None", "group_cipher": "None",
     "rsn_capabilities": 0x0000},
    {"bssid": "00:13:49:77:88:01", "ssid": "lab-corpwpa3", "vendor_oui": "001349",
     "security_mode": "wpa3_only", "pmf_capable": True, "pmf_required": True,
     "akm_suite": "SAE", "pairwise_cipher": "CCMP", "group_cipher": "CCMP",
     "rsn_capabilities": 0x00CF},
    {"bssid": "00:1e:58:aa:bb:01", "ssid": "lab-legacynet", "vendor_oui": "001e58",
     "security_mode": "wep", "pmf_capable": False, "pmf_required": False,
     "akm_suite": "WEP", "pairwise_cipher": "WEP", "group_cipher": "WEP",
     "rsn_capabilities": 0x0000},
    {"bssid": "00:23:cd:cc:dd:01", "ssid": "lab-enterprise", "vendor_oui": "0023cd",
     "security_mode": "wpa2_only", "pmf_capable": True, "pmf_required": False,
     "akm_suite": "EAP", "pairwise_cipher": "CCMP", "group_cipher": "CCMP",
     "rsn_capabilities": 0x00CC},
    {"bssid": "00:14:6c:11:22:01", "ssid": "lab-dualband", "vendor_oui": "00146c",
     "security_mode": "transition", "pmf_capable": True, "pmf_required": False,
     "akm_suite": "PSK+SAE", "pairwise_cipher": "CCMP", "group_cipher": "CCMP",
     "rsn_capabilities": 0x00CC},
    {"bssid": "00:13:49:33:44:01", "ssid": "lab-newdeploy", "vendor_oui": "001349",
     "security_mode": "wpa3_only", "pmf_capable": True, "pmf_required": True,
     "akm_suite": "SAE", "pairwise_cipher": "CCMP", "group_cipher": "CCMP",
     "rsn_capabilities": 0x00CF},
]

SECURITY_LABELS = {"open": "Open", "wep": "WEP", "wpa2_only": "WPA2-Only",
                   "transition": "WPA3-Transition", "wpa3_only": "WPA3-Only"}

# ----------------------------------------------------------------------
# AKM suite identifiers (0x0F:AC:<num>)
# ----------------------------------------------------------------------
AKM_PSK = 0x02
AKM_SAE = 0x08
AKM_SUITE_NAMES = {AKM_PSK: "PSK", AKM_SAE: "SAE"}


def classify_ap(ap):
    return SECURITY_LABELS.get(ap["security_mode"], "Unknown")


def lookup_vendor(oui):
    return OUI_TABLE.get(oui.lower(), f"Unknown ({oui})")


def compute_census(aps):
    mode_counts = Counter()
    vendor_counts = Counter()
    pmf_capable = pmf_required = 0
    total = len(aps)
    for ap in aps:
        mode_counts[classify_ap(ap)] += 1
        vendor_counts[lookup_vendor(ap["vendor_oui"])] += 1
        if ap["pmf_capable"]:
            pmf_capable += 1
        if ap["pmf_required"]:
            pmf_required += 1
    return {"total": total, "mode_counts": dict(mode_counts),
            "vendor_counts": dict(vendor_counts),
            "pmf_capable_count": pmf_capable, "pmf_required_count": pmf_required,
            "percentages": {k: round(v / total * 100, 1) for k, v in mode_counts.items()}
            if total else {}}


# ----------------------------------------------------------------------
# Byte-level beacon survey (RSN IE -> WPA3/SAE classification off the wire)
# ----------------------------------------------------------------------


def akm_from_rsn(rsn_ie_payload: bytes) -> list[int]:
    """Parse the AKM suite identifiers out of an RSNE body."""
    if len(rsn_ie_payload) < 8:
        return []
    off = 2                       # version
    off += 2                      # group cipher suite
    pcount = struct.unpack("<H", rsn_ie_payload[off:off + 2])[0]
    off += 2 + pcount * 4
    acount = struct.unpack("<H", rsn_ie_payload[off:off + 2])[0]
    off += 2
    akms = []
    for _ in range(acount):
        suite = rsn_ie_payload[off:off + 4]
        if len(suite) == 4 and suite[0:3] == b"\x00\x0f\xac":
            akms.append(suite[3])
        off += 4
    return akms


def sae_capabilities_byte(rsn_ie_payload: bytes) -> int:
    """RSN capabilities bit 6 = PMF required (MFP-req)."""
    if len(rsn_ie_payload) < 10:
        return 0
    cap = rsn_ie_payload[8]
    return cap


def build_ap_beacon(ap: dict) -> bytes:
    """Build a beacon with the correct RSN/AKM to represent this AP."""
    akms = []
    if ap["akm_suite"] == "PSK":
        akms = [AKM_PSK]
    elif ap["akm_suite"] == "SAE":
        akms = [AKM_SAE]
    elif ap["akm_suite"] == "PSK+SAE":
        akms = [AKM_PSK, AKM_SAE]
    elif ap["akm_suite"] == "EAP":
        akms = []
    rsn = None
    if akms:
        cap = ap.get("rsn_capabilities", 0)
        rsn = fc.build_rsn_ie(pairwise=[0x04], group=0x04, akm=akms,
                              capabilities=cap & 0xFFFF)
    return fc.build_beacon(ap["bssid"], ssid=ap["ssid"], timestamp=0,
                           beacon_interval=100, seq_num=1, rsn=rsn)


def classify_from_beacon(data: bytes) -> dict:
    """Classify an AP directly from beacon bytes via RSN IE."""
    if fc.verify_fcs(data):
        data = data[:-4]
    fields, ies = fc.parse_beacon(data)
    akms = []
    for ie in ies:
        if ie["id"] == fc.IE_RSN and not ie["malformed"]:
            akms = akm_from_rsn(ie["value"])
    has_sae = AKM_SAE in akms
    has_psk = AKM_PSK in akms
    if has_sae and has_psk:
        mode = "WPA3-Transition"
    elif has_sae:
        mode = "WPA3-Only"
    elif has_psk:
        mode = "WPA2-Only"
    else:
        mode = "Open"
    return {"bssid": fields["bssid"], "ssid": fields["ssid"] or "<hidden>",
            "akms": [AKM_SUITE_NAMES.get(a, f"akm-{a}") for a in akms],
            "mode": mode, "has_sae": has_sae}


def build_survey_beacons() -> list[dict]:
    out = []
    for ap in SAMPLE_APS:
        if ap["akm_suite"] in ("WEP", "EAP"):
            continue          # not representable via RSN AKM; covered by record census
        data = build_ap_beacon(ap)
        data += fc.fcs(data)
        out.append({"bssid": ap["bssid"], "ssid": ap["ssid"], "data": data,
                    "expected": classify_ap(ap)})
    return out


# ----------------------------------------------------------------------
# SAE (Dragonfly) handshake byte-sequence engineering
# ----------------------------------------------------------------------


def build_sae_sequence(ap_mac: str = "00:11:22:33:44:55",
                       sta_mac: str = "00:11:22:33:44:66") -> list[dict]:
    """Build the SAE auth commit/confirm byte sequence (offline simulation)."""
    seq = []
    # 1. Probe/assoc context beacon advertising SAE AKM
    beacon = fc.build_beacon(ap_mac, ssid="lab-wpa3", timestamp=0,
                             beacon_interval=100, seq_num=1,
                             rsn=fc.build_rsn_ie(pairwise=[0x04], group=0x04,
                                                 akm=[AKM_SAE], capabilities=0x00CF))
    seq.append({"phase": "beacon-sae", "kind": "beacon",
                "data": beacon,
                "note": "AP advertises SAE AKM + PMF-required"})

    # 2. Auth commit from STA (open/SAE alg=3, transaction 1, status 0)
    # SAE commit carries a scalar + element; we model the reserved/placeholder body.
    commit_body = bytes(range(32))          # placeholder 32-byte scalar record
    auth_commit = fc.build_auth(ap_mac, sta_mac, ap_mac, auth_alg=fc.AUTH_ALG_SAE,
                                transaction=1, status=0, seq_num=2) + commit_body
    seq.append({"phase": "auth-commit-sta", "kind": "auth-commit",
                "data": auth_commit,
                "note": "SAE commit (scalar + PWE element) from STA, tx=1"})

    # 3. Auth confirm from AP (transaction 2, y = sntk)
    confirm_body = bytes([0x01]) * 32       # placeholder confirm (sntk)
    auth_confirm = fc.build_auth(sta_mac, ap_mac, ap_mac, auth_alg=fc.AUTH_ALG_SAE,
                                 transaction=2, status=0, seq_num=3) + confirm_body
    seq.append({"phase": "auth-confirm-ap", "kind": "auth-confirm",
                "data": auth_confirm,
                "note": "SAE confirm from AP, tx=2"})

    # 4. STA auth confirm (transaction 2 reply)
    auth_sta_confirm = fc.build_auth(ap_mac, sta_mac, ap_mac, auth_alg=fc.AUTH_ALG_SAE,
                                     transaction=2, status=0, seq_num=4) + confirm_body
    seq.append({"phase": "auth-confirm-sta", "kind": "auth-confirm",
                "data": auth_sta_confirm,
                "note": "SAE confirm from STA, tx=2"})
    return seq


def print_sae_sequence(seq: list[dict]) -> None:
    print("--- SAE Handshake Sequence (offline bytes) ---")
    for e in seq:
        print(f"  {e['phase']:20s} {e['kind']:16s} ({len(e['data']):3d}B)  {e['note']}")
        print(f"     {e['data'].hex()}")


# ----------------------------------------------------------------------
# CLI / demo
# ----------------------------------------------------------------------


def run_survey(byte_level: bool) -> dict:
    if byte_level:
        rows = []
        for b in build_survey_beacons():
            rows.append({**classify_from_beacon(b["data"]),
                         "expected": b["expected"],
                         "match": classify_from_beacon(b["data"])["mode"] == b["expected"]})
        result = {"name": "w10-wpa3-survey", "radio_emitted": False,
                  "survey_source": "byte-level beacons (RSN IE)",
                  "beacons": rows}
        result["census"] = compute_census(SAMPLE_APS)
        result["all_classified_correctly"] = all(r["match"] for r in rows)
        return result
    result = {"name": "w10-wpa3-survey", "radio_emitted": False,
              "survey_source": "record-level corpus",
              "census": compute_census(SAMPLE_APS)}
    return result


def build_args_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="w10-wpa3-survey",
        description="WPA3-adoption census + SAE handshake byte-sequence engineering "
                    "(pure-stdlib bytes; offline; no radio).")
    p.add_argument("--survey", choices=["beacon", "record"], default="beacon",
                   help="census source: RSN IE from byte-level beacons (default) or records.")
    p.add_argument("--sae", action="store_true",
                   help="print the SAE auth commit/confirm byte sequence (offline).")
    p.add_argument("--json", metavar="PATH", help="write JSON report.")
    return p


def print_census(census: dict) -> None:
    print("--- Security Mode Census ---")
    for mode in ["Open", "WEP", "WPA2-Only", "WPA3-Transition", "WPA3-Only"]:
        c = census["mode_counts"].get(mode, 0)
        pct = census["percentages"].get(mode, 0)
        print(f"  {mode:<18s} {c:>3d}  ({pct:>5.1f}%)")
    wpa3 = census["mode_counts"].get("WPA3-Only", 0) + \
        census["mode_counts"].get("WPA3-Transition", 0)
    print(f"\n  Total: {census['total']}   PMF capable: {census['pmf_capable_count']}  "
          f"PMF required: {census['pmf_required_count']}  WPA3 coverage: {wpa3}")


def main(argv=None) -> int:
    args = build_args_parser().parse_args(argv)
    result = run_survey(args.survey == "beacon")
    print("=" * 66)
    print("W10 — WPA3 Transition-Mode Neighborhood Survey & SAE Engineering")
    print("=" * 66)
    print(f"\n[+] Census source: {result['survey_source']}   (radio_emitted=False)\n")
    if args.survey == "beacon":
        print("--- AP classification from RSN IE (byte-level) ---")
        for b in result["beacons"]:
            flag = "OK" if b["match"] else "MISMATCH"
            print(f"  [{flag:8s}] {b['bssid']}  {b['ssid']:<16s}  AKMs={b['akms']}  "
                  f"mode={b['mode']}  (expected {b['expected']})")
        print(f"\n  All classified correctly: {result['all_classified_correctly']}\n")
    print_census(result["census"])
    sae_seq = []
    if args.sae:
        sae_seq = build_sae_sequence()
        print("\n")
        print_sae_sequence(sae_seq)
    if args.json:
        result["sae_sequence"] = [{"phase": e["phase"], "kind": e["kind"],
                                   "note": e["note"], "hex": e["data"].hex()}
                                  for e in sae_seq]
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2, default=str)
    print("\nOffline survey complete — no radio emitted.")
    print("=" * 66)
    return 0


def run_demo() -> int:
    return main(["--survey", "beacon", "--sae"])


if __name__ == "__main__":
    raise SystemExit(main())
