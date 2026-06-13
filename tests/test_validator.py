"""Tests for the 3-layer finding validator (ported from Sentinel Ensemble logic):
  Layer 1 — trace gate      (every claim must appear in a real Splunk row)
  Layer 2 — corroboration   (distinct independent sourcetypes backing it)
  Layer 3 — calibration     (3+ sources=HIGH, 2=MEDIUM, 1=LOW)
Runnable with pytest OR `python3 tests/test_validator.py` (no pytest needed)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from finding_validator import validate_finding  # noqa: E402

# Three rows from three independent sourcetypes (auth, firewall, web).
EV_3SRC = [
    {"sourcetype": "linux_secure", "src_ip": "203.0.113.66", "user": "svc_backup", "count": "45"},
    {"sourcetype": "cisco:asa", "src_ip": "10.10.0.42", "dest_ip": "198.51.100.23", "bytes_out": "912340000"},
    {"sourcetype": "access_combined", "src_ip": "203.0.113.66", "uri": "/admin", "status": "403"},
]


def test_layer1_blocks_unsupported_claim():
    f = {"id": "F", "title": "x", "claims": [{"field": "src_ip", "value": "10.9.9.9"}]}
    v = validate_finding(f, EV_3SRC)
    assert v["layers"]["layer1_trace"]["passed"] is False
    assert v["disposition"] == "rejected"
    assert v["confidence"] == "NONE"


def test_layer1_pass_confirms():
    f = {"id": "F", "title": "x", "claims": [{"field": "src_ip", "value": "203.0.113.66"}]}
    v = validate_finding(f, EV_3SRC)
    assert v["layers"]["layer1_trace"]["passed"] is True
    assert v["disposition"] == "confirmed"


def test_layer3_high_three_independent_sources():
    f = {"id": "F", "title": "x", "claims": [
        {"field": "src_ip", "value": "203.0.113.66"},     # linux_secure + access_combined
        {"field": "dest_ip", "value": "198.51.100.23"},   # cisco:asa
    ]}
    v = validate_finding(f, EV_3SRC)
    assert v["disposition"] == "confirmed"
    assert v["layers"]["layer2_corroboration"]["count"] == 3
    assert v["confidence"] == "HIGH"


def test_layer3_medium_two_sources():
    f = {"id": "F", "title": "x", "claims": [{"field": "src_ip", "value": "203.0.113.66"}]}
    v = validate_finding(f, EV_3SRC)            # matches linux_secure + access_combined
    assert v["layers"]["layer2_corroboration"]["count"] == 2
    assert v["confidence"] == "MEDIUM"


def test_layer3_low_single_source():
    rows = [{"sourcetype": "linux_secure", "src_ip": "203.0.113.66"}]
    f = {"id": "F", "title": "x", "claims": [{"field": "src_ip", "value": "203.0.113.66"}]}
    v = validate_finding(f, rows)
    assert v["confidence"] == "LOW"


def test_backward_compat_untagged_rows():
    rows = [{"src_ip": "203.0.113.66"}]          # no sourcetype field
    f = {"id": "F", "claims": [{"field": "src_ip", "value": "203.0.113.66"}]}
    v = validate_finding(f, rows)
    assert v["disposition"] == "confirmed"
    assert v["confidence"] == "LOW"              # confirmed => implicit single source


def test_partial_support_needs_review():
    f = {"id": "F", "claims": [
        {"field": "src_ip", "value": "203.0.113.66"},   # supported
        {"field": "src_ip", "value": "1.2.3.4"},        # not present
    ]}
    v = validate_finding(f, EV_3SRC)
    assert v["disposition"] == "needs_review"
    assert v["confidence"] == "NONE"


def test_no_claims_is_inconclusive():
    v = validate_finding({"id": "F", "claims": []}, EV_3SRC)
    assert v["disposition"] == "inconclusive"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
