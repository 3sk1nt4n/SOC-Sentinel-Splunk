"""SOC Sentinel's core differentiator (ported from Sentinel Ensemble):
code, not the model, decides what's confirmed. Every claim a finding makes must
trace to a value actually present in the Splunk search results that produced it.
A claim with no matching row is flagged UNSUPPORTED and never reported as fact."""
from typing import Any


def _row_has(field: str, value: str, results: list[dict]) -> bool:
    v = str(value)
    for row in results:
        cell = str(row.get(field, ""))
        if cell == v or (v and v in cell):
            return True
    return False


def validate_finding(finding: dict[str, Any], results: list[dict]) -> dict[str, Any]:
    """Check each claim (field=value) against the Splunk rows. Returns per-claim
    verdicts + a disposition. Confirmed ONLY if every claim traces to a row."""
    claims = finding.get("claims") or []
    verdicts = [{**c, "supported": _row_has(c.get("field", ""), c.get("value", ""), results)}
                for c in claims]
    all_ok = bool(verdicts) and all(c["supported"] for c in verdicts)
    return {
        "finding_id": finding.get("id"),
        "title": finding.get("title"),
        "claims": verdicts,
        "disposition": "confirmed" if all_ok else "needs_review",
        "trace": [f"{c.get('field')}={c.get('value')} -> {'✓ in Splunk results' if c['supported'] else '✗ UNSUPPORTED'}"
                  for c in verdicts],
    }
