"""SOC Sentinel's core differentiator — a 3-layer trust pipeline over every AI
finding, reimplemented from Sentinel Ensemble's logic for Splunk.

Code, not the model, decides what is reported as fact:

  Layer 1 — TRACE GATE          every claim (field=value) must appear in a real
                                Splunk result row, or it is UNSUPPORTED. (Ensemble:
                                deterministic validator + paired reference set.)
  Layer 2 — CORROBORATION       count the distinct *independent sourcetypes* that
                                back the finding — the Splunk analog of Ensemble's
                                memory+disk+logs cross-artifact agreement.
  Layer 3 — CALIBRATION         evidence-based confidence: 3+ independent sources
                                = HIGH, 2 = MEDIUM, 1 = LOW. (Ensemble: 3+ artifact
                                types = HIGH.)

Disposition: confirmed (all claims trace) / needs_review (some) / rejected (none)
/ inconclusive (no claims). Confidence is only assigned to confirmed findings.
Universal + behavioural — no case-specific values are baked in."""
from typing import Any

CONFIDENCE_RULE = "3+ independent sources = HIGH, 2 = MEDIUM, 1 = LOW"
_SOURCE_FIELDS = ("sourcetype", "source", "index")


def _source_of(row: dict) -> str | None:
    for k in _SOURCE_FIELDS:
        val = row.get(k)
        if val:
            return str(val)
    return None


def _supporting_rows(field: str, value: str, results: list[dict]) -> list[dict]:
    v = str(value)
    out = []
    for row in results:
        cell = str(row.get(field, ""))
        if cell == v or (v and v in cell):
            out.append(row)
    return out


def validate_finding(finding: dict[str, Any], results: list[dict]) -> dict[str, Any]:
    """Run the 3-layer pipeline for one finding against the Splunk result rows."""
    claims = finding.get("claims") or []

    # ---- Layer 1: trace gate ------------------------------------------------
    verdicts = []
    supporting: list[dict] = []
    for c in claims:
        rows = _supporting_rows(c.get("field", ""), c.get("value", ""), results)
        verdicts.append({**c, "supported": bool(rows)})
        supporting.extend(rows)
    n_supported = sum(1 for v in verdicts if v["supported"])
    layer1_pass = bool(verdicts) and n_supported == len(verdicts)

    if not claims:
        disposition = "inconclusive"
    elif layer1_pass:
        disposition = "confirmed"
    elif n_supported == 0:
        disposition = "rejected"
    else:
        disposition = "needs_review"

    # ---- Layer 2: corroboration --------------------------------------------
    sources = sorted({s for s in (_source_of(r) for r in supporting) if s})
    n_sources = len(sources)
    if disposition == "confirmed" and n_sources == 0:
        n_sources = 1   # confirmed but rows were untagged -> single implicit source

    # ---- Layer 3: calibration ----------------------------------------------
    if disposition != "confirmed":
        confidence = "NONE"
    elif n_sources >= 3:
        confidence = "HIGH"
    elif n_sources == 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "finding_id": finding.get("id"),
        "title": finding.get("title"),
        "disposition": disposition,
        "confidence": confidence,
        "claims": verdicts,
        "trace": [
            f"{c.get('field')}={c.get('value')} -> "
            f"{'✓ in Splunk results' if c['supported'] else '✗ UNSUPPORTED'}"
            for c in verdicts
        ],
        "layers": {
            "layer1_trace": {
                "passed": layer1_pass,
                "supported": n_supported,
                "total": len(verdicts),
                "summary": f"{n_supported}/{len(verdicts)} claims trace to real Splunk rows",
            },
            "layer2_corroboration": {
                "sources": sources,
                "count": n_sources,
                "summary": (f"{n_sources} independent source(s)"
                            + (f": {', '.join(sources)}" if sources else " (single/untagged)")),
            },
            "layer3_calibration": {
                "confidence": confidence,
                "rule": CONFIDENCE_RULE,
            },
        },
    }
