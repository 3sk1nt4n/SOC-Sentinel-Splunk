"""Guard tests for the universal detection library — structure + no answer keys.
Pure unit tests (no Splunk needed): `python3 tests/test_detections.py` or pytest."""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from detections import DEFAULT_THRESHOLDS, DETECTIONS  # noqa: E402

_REQUIRED = {"domain", "id", "tactic", "technique", "title", "entity", "spl"}


def test_multicloud_and_domain_coverage():
    domains = {d["domain"] for d in DETECTIONS}
    for need in ("identity", "endpoint", "network", "aws", "azure", "gcp"):
        assert need in domains, f"missing domain coverage: {need}"


def test_each_detector_well_formed():
    for d in DETECTIONS:
        assert _REQUIRED <= set(d), f"{d.get('id')} missing keys: {_REQUIRED - set(d)}"
        assert d["technique"].startswith("T"), f"{d['id']} technique not a MITRE id"


def test_ids_unique():
    ids = [d["id"] for d in DETECTIONS]
    assert len(ids) == len(set(ids)), "duplicate detector ids"


def test_spl_templates_format_cleanly():
    # Every template must render with {index} + the default thresholds (no KeyError).
    for d in DETECTIONS:
        spl = d["spl"].format(index="soc_demo", **DEFAULT_THRESHOLDS)
        assert "{" not in spl, f"{d['id']} has an unfilled placeholder: {spl}"
        assert spl.lower().startswith("search") or spl.startswith("|"), d["id"]


def test_no_answer_keys():
    """No detector may hardcode the demo's CONCRETE IOCs (specific attacker IPs, the
    compromised usernames, the demo service/bucket/domain names). Universal structural
    patterns (0.0.0.0/0, lsass.exe, AdministratorAccess, roles/owner, allUsers) are
    fine — those generalise to any environment; that is the whole point."""
    demo_iocs = ["203.0.113.66", "198.51.100.23", "10.10.0.42",
                 "svc_backup", "svc-deploy", "WinDefendUpd",
                 "corp-backups-prod", "corp-gcp-backups", "evil-c2.example", "evil.example"]
    for d in DETECTIONS:
        for ioc in demo_iocs:
            assert ioc not in d["spl"], f"{d['id']} hardcodes demo IOC {ioc}"


def test_high_value_coverage():
    """The Find-Evil-grade high-value detectors must be present (log-native ports)."""
    ids = {d["id"] for d in DETECTIONS}
    for need in ("credential_dump", "recon_burst", "psexec_lateral", "rdp_lateral",
                 "wmi_persistence", "process_masquerade", "antiforensics_deletion", "ransomware_prep",
                 "process_injection", "process_hollowing", "reflective_dll_load"):
        assert need in ids, f"missing high-value detector: {need}"


def test_kill_chain_breadth():
    tactics = {d["tactic"] for d in DETECTIONS}
    # We claim ATT&CK breadth — require coverage of the core phases.
    for need in ("Credential Access", "Execution", "Persistence",
                 "Lateral Movement", "Command and Control", "Exfiltration"):
        assert need in tactics, f"missing tactic coverage: {need}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
