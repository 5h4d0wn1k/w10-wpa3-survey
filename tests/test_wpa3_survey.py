#!/usr/bin/env python3
"""Byte-exact unit tests for w10-wpa3-survey."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import wpa3_survey as ws
from firmware import frame_core as fc


class RSNIETest(unittest.TestCase):
    def test_rsn_roundtrip(self):
        rsn = fc.build_rsn_ie(pairwise=[0x04], group=0x04, akm=[ws.AKM_SAE],
                              capabilities=0x00CF)
        ies = fc.parse_ie_sequence(rsn)
        self.assertEqual(ies[0]["id"], fc.IE_RSN)
        akms = ws.akm_from_rsn(ies[0]["value"])
        self.assertIn(ws.AKM_SAE, akms)

    def test_akm_parsing_psk_and_sae(self):
        rsn = fc.build_rsn_ie(akm=[ws.AKM_PSK, ws.AKM_SAE])
        akms = ws.akm_from_rsn(fc.parse_ie_sequence(rsn)[0]["value"])
        self.assertEqual(akms, [ws.AKM_PSK, ws.AKM_SAE])


class BeaconSurveyTest(unittest.TestCase):
    def test_wpa3_only_classified_from_bytes(self):
        ap = {"bssid": "00:13:49:77:88:01", "ssid": "lab-corpwpa3",
              "akm_suite": "SAE", "rsn_capabilities": 0x00CF}
        data = ws.build_ap_beacon(ap) + fc.fcs(ws.build_ap_beacon(ap))
        cls = ws.classify_from_beacon(data)
        self.assertEqual(cls["mode"], "WPA3-Only")
        self.assertTrue(cls["has_sae"])

    def test_transition_classified_from_bytes(self):
        ap = {"bssid": "00:1a:2b:33:44:02", "ssid": "lab-officenet",
              "akm_suite": "PSK+SAE", "rsn_capabilities": 0x00CF}
        data = ws.build_ap_beacon(ap) + fc.fcs(ws.build_ap_beacon(ap))
        cls = ws.classify_from_beacon(data)
        self.assertEqual(cls["mode"], "WPA3-Transition")

    def test_open_has_no_sae(self):
        ap = {"bssid": "00:14:6c:55:66:01", "ssid": "lab-cafeopen",
              "akm_suite": "None", "rsn_capabilities": 0x0000}
        data = ws.build_ap_beacon(ap) + fc.fcs(ws.build_ap_beacon(ap))
        cls = ws.classify_from_beacon(data)
        self.assertEqual(cls["mode"], "Open")
        self.assertFalse(cls["has_sae"])

    def test_survey_all_classified(self):
        result = ws.run_survey(byte_level=True)
        self.assertTrue(result["all_classified_correctly"])
        # only APs representable via RSN AKM are beacon-classified (WEP/EAP excluded)
        representable = [ap for ap in ws.SAMPLE_APS if ap["akm_suite"] not in ("WEP", "EAP")]
        self.assertEqual(len(result["beacons"]), len(representable))


class SAETest(unittest.TestCase):
    def test_sae_sequence_has_commit_and_confirm(self):
        seq = ws.build_sae_sequence()
        kinds = [e["kind"] for e in seq]
        self.assertIn("auth-commit", kinds)
        self.assertIn("auth-confirm", kinds)

    def test_commit_uses_sae_algo(self):
        seq = ws.build_sae_sequence()
        commit = [e for e in seq if e["kind"] == "auth-commit"][0]
        # header + note: parse the auth frame (strip commit body after 6-byte auth body)
        # auth frame body is 6 bytes: alg(2) + tx(2) + status(2)
        header = commit["data"][:24]
        auth_fields, rest = fc.parse_mgmt_header(header)
        self.assertEqual(auth_fields["subtype_val"], fc.FC_SUBTYPE_AUTH)
        parsed_auth = fc.parse_auth(commit["data"][:30])
        self.assertEqual(parsed_auth["auth_alg"], fc.AUTH_ALG_SAE)
        self.assertEqual(parsed_auth["transaction"], 1)


class ReportTest(unittest.TestCase):
    def test_json(self):
        r = ws.run_survey(byte_level=True)
        json.dumps(r, default=str)

    def test_cli_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "o.json")
            rc = ws.main(["--survey", "beacon", "--json", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))

    def test_demo_exit_zero(self):
        self.assertEqual(ws.run_demo(), 0)


if __name__ == "__main__":
    unittest.main()
