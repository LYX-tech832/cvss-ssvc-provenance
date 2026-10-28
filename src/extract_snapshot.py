"""Extract one row per published CVE record from the CVE List snapshot of 2026-09-25.

Input:  a zip file with the cves/ directory of the CVE List snapshot (CVE JSON 5 records under
        cves/<year>/<bucket>/CVE-*.json), given as the first argument
Output: data/snapshot_records.parquet and data/snapshot_records.meta.json (input hash, row counts)

Columns
  cve, assigner, date_published, date_updated            cveMetadata
  cna                                                    CNA providerMetadata.shortName (the CNA that wrote the container)
  cna_date_updated                                       CNA providerMetadata.dateUpdated
  cna_v3, cna_v3_version, cna_v4                         CNA CVSS vector strings (v3.1 preferred over v3.0)
  cna_desc                                               first English CNA description
  cwe_cna, cwe_adp                                       CWE ids, joined by "|"
  ref_tags, n_refs                                       CNA reference tags (unique, sorted, "|"), number of references
  vendor, product, n_affected, has_cpe                   first CNA affected entry; CPE present in affected or cpeApplicability
  cpe_parts                                              CPE 2.3 "part" letters found in the CNA container (a, o, h), sorted
  collection_urls, has_package_name                      CNA affected[].collectionURL values ("|"), any affected[].packageName
  cisa_date_updated, cisa_v3                             CISA-ADP container: providerMetadata.dateUpdated, CVSS v3.1 vector
  ssvc_exploitation, ssvc_automatable, ssvc_technical_impact, ssvc_timestamp, ssvc_role, ssvc_version
  kev, kev_date_added                                    KEV block in the CISA-ADP container

Runtime: a few minutes on a laptop (reads about 400,000 JSON files from the zip).
"""

import hashlib
import json
import sys
import zipfile
from pathlib import Path

import orjson
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "snapshot_records.parquet"


def first_vector(metrics, keys):
    for m in metrics or []:
        for k in keys:
            if k in m and m[k].get("vectorString"):
                return m[k]["vectorString"], k
    return None, None


def cwes(problem_types):
    ids = set()
    for pt in problem_types or []:
        for d in pt.get("descriptions", []) or []:
            if d.get("cweId"):
                ids.add(d["cweId"])
    return "|".join(sorted(ids)) or None


def cpe_parts(cna):
    """CPE 2.3 part letters (a = application, o = operating system, h = hardware) in the CNA container."""
    names = []
    for a in cna.get("affected", []) or []:
        names.extend(a.get("cpes", []) or [])
    stack = list(cna.get("cpeApplicability", []) or [])
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for m in node.get("cpeMatch", []) or []:
                if m.get("criteria"):
                    names.append(m["criteria"])
            stack.extend(node.get("nodes", []) or [])
            stack.extend(node.get("children", []) or [])
        elif isinstance(node, list):
            stack.extend(node)
    parts = {n.split(":")[2] for n in names if isinstance(n, str) and n.startswith("cpe:2.3:") and len(n.split(":")) > 2}
    return "".join(sorted(parts & {"a", "o", "h"})) or None


def row(d):
    meta = d.get("cveMetadata", {})
    cont = d.get("containers", {})
    cna = cont.get("cna", {}) or {}
    v3, v3key = first_vector(cna.get("metrics"), ("cvssV3_1", "cvssV3_0"))
    v4, _ = first_vector(cna.get("metrics"), ("cvssV4_0",))
    affected = cna.get("affected", []) or []
    first = affected[0] if affected else {}
    refs = cna.get("references", []) or []
    r = {
        "cve": meta.get("cveId"),
        "assigner": meta.get("assignerShortName"),
        "cna": (cna.get("providerMetadata") or {}).get("shortName"),
        "date_published": meta.get("datePublished"),
        "date_updated": meta.get("dateUpdated"),
        "cna_date_updated": (cna.get("providerMetadata") or {}).get("dateUpdated"),
        "cna_v3": v3,
        "cna_v3_version": {"cvssV3_1": "3.1", "cvssV3_0": "3.0"}.get(v3key),
        "cna_v4": v4,
        "cna_desc": next((x.get("value") for x in cna.get("descriptions", []) or []
                          if str(x.get("lang", "")).startswith("en")), None),
        "cwe_cna": cwes(cna.get("problemTypes")),
        "cwe_adp": None,
        "ref_tags": "|".join(sorted({t for rf in refs for t in (rf.get("tags") or [])})) or None,
        "n_refs": len(refs),
        "vendor": first.get("vendor"),
        "product": first.get("product"),
        "n_affected": len(affected),
        "has_cpe": bool(cna.get("cpeApplicability")) or any(a.get("cpes") for a in affected),
        "cpe_parts": cpe_parts(cna),
        "collection_urls": "|".join(sorted({a["collectionURL"] for a in affected if a.get("collectionURL")})) or None,
        "has_package_name": any(a.get("packageName") for a in affected),
        "cisa_date_updated": None,
        "cisa_v3": None,
        "ssvc_exploitation": None,
        "ssvc_automatable": None,
        "ssvc_technical_impact": None,
        "ssvc_timestamp": None,
        "ssvc_role": None,
        "ssvc_version": None,
        "kev": False,
        "kev_date_added": None,
    }
    adp_cwes = set()
    for a in cont.get("adp", []) or []:
        c = cwes(a.get("problemTypes"))
        if c:
            adp_cwes.update(c.split("|"))
        if (a.get("providerMetadata") or {}).get("shortName") != "CISA-ADP":
            continue
        r["cisa_date_updated"] = (a.get("providerMetadata") or {}).get("dateUpdated")
        v, _ = first_vector(a.get("metrics"), ("cvssV3_1",))
        r["cisa_v3"] = v
        for m in a.get("metrics", []) or []:
            o = m.get("other") or {}
            content = o.get("content") or {}
            if o.get("type") == "ssvc":
                opts = {}
                for kv in content.get("options", []) or []:
                    opts.update(kv)
                r["ssvc_exploitation"] = opts.get("Exploitation")
                r["ssvc_automatable"] = opts.get("Automatable")
                r["ssvc_technical_impact"] = opts.get("Technical Impact")
                r["ssvc_timestamp"] = content.get("timestamp")
                r["ssvc_role"] = content.get("role")
                r["ssvc_version"] = content.get("version")
            elif o.get("type") == "kev":
                r["kev"] = True
                r["kev_date_added"] = content.get("dateAdded")
    r["cwe_adp"] = "|".join(sorted(adp_cwes)) or None
    return r


def main(src):
    src = Path(src)
    sha = hashlib.sha256(src.read_bytes()).hexdigest()
    rows, skipped = [], 0
    with zipfile.ZipFile(src) as z:
        for name in z.namelist():
            if not (name.startswith("cves/") and name.endswith(".json")):
                continue
            try:
                d = orjson.loads(z.read(name))
            except orjson.JSONDecodeError:
                skipped += 1
                continue
            if not isinstance(d, dict) or d.get("cveMetadata", {}).get("state") != "PUBLISHED":
                continue
            rows.append(row(d))
    df = pd.DataFrame(rows).sort_values("cve").reset_index(drop=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(OUT, index=False)
    meta = {
        "source": src.name, "source_sha256": sha, "rows": len(df), "unparsable_files": skipped,
        "with_ssvc": int(df.ssvc_timestamp.notna().sum()), "with_cna_v3": int(df.cna_v3.notna().sum()),
        "with_cna_v4": int(df.cna_v4.notna().sum()), "with_cisa_v3": int(df.cisa_v3.notna().sum()),
        "kev": int(df.kev.sum()),
    }
    OUT.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print(json.dumps(meta, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
