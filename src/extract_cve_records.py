"""Build the CVSS label table from a complete snapshot of the CVE List V5.

Input: the release file `<date>_all_CVEs_at_midnight.zip.zip` of the cvelistV5 repository (an outer zip that contains one
inner zip with the CVE JSON 5 records).
Output: data/processed/cve_records.parquet, one row per record in state PUBLISHED, with
  cve_id, date_published, date_updated, date_reserved, assigner_short_name, assigner_org_id,
  cna_short_name, cna_org_id (providerMetadata of the CNA container), title, description (English, CNA container),
  cwe_cna, cwe_adp (CWE identifiers in order of appearance, de-duplicated),
  cna_v40, cna_v31 (valid base vectors of the CNA container, normalised and de-duplicated),
  adp_v40, adp_v31 ("<ADP short name>|<base vector>"), data_version;
and data/processed/cve_records.provenance.json (input hash and counts).

Usage (from the project root):
    python src/extract_cve_records.py <path to 2026-09-25_all_CVEs_at_midnight.zip.zip>
"""

import hashlib
import json
import sys
import zipfile
from pathlib import Path

import orjson
import pandas as pd
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import base_vector, parse_vector  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "processed"

# key of each CVSS version's object in CVE JSON 5
CVSS_KEYS = {"cvssV4_0": "4.0", "cvssV3_1": "3.1"}


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_inner_zip(outer_path, work_dir):
    """The outer zip holds exactly one inner zip; extract it into work_dir (once)."""
    with zipfile.ZipFile(outer_path) as outer:
        members = [m for m in outer.namelist() if m.endswith(".zip")]
        if len(members) != 1:
            raise ValueError(f"expected exactly one inner zip in the outer zip, found: {outer.namelist()[:5]}")
        inner_path = Path(work_dir) / Path(members[0]).name
        if not inner_path.exists():
            outer.extract(members[0], work_dir)
            extracted = Path(work_dir) / members[0]
            if extracted != inner_path:
                extracted.rename(inner_path)
    return inner_path


def english_description(container):
    for d in container.get("descriptions") or []:
        if str(d.get("lang", "")).lower().startswith("en") and d.get("value"):
            return d["value"].strip()
    return None


def cwe_ids(container):
    out = []
    for pt in container.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cwe = d.get("cweId")
            if cwe and cwe not in out:
                out.append(cwe)
    return out


def cvss_vectors(container, version):
    """All valid base vectors of one version in a container (normalised, de-duplicated, in order of appearance)."""
    out = []
    for m in container.get("metrics") or []:
        for key, ver in CVSS_KEYS.items():
            if ver == version and key in m:
                parsed = parse_vector((m[key] or {}).get("vectorString"), version)
                if parsed:
                    vec = base_vector(parsed, version)
                    if vec not in out:
                        out.append(vec)
    return out


def extract_record(rec):
    meta = rec.get("cveMetadata") or {}
    if meta.get("state") != "PUBLISHED":
        return None
    containers = rec.get("containers") or {}
    cna = containers.get("cna") or {}
    cna_meta = cna.get("providerMetadata") or {}

    adp_v40, adp_v31, adp_cwe = [], [], []
    for adp in containers.get("adp") or []:
        name = (adp.get("providerMetadata") or {}).get("shortName") or "UNKNOWN_ADP"
        adp_v40 += [f"{name}|{v}" for v in cvss_vectors(adp, "4.0")]
        adp_v31 += [f"{name}|{v}" for v in cvss_vectors(adp, "3.1")]
        adp_cwe += [c for c in cwe_ids(adp) if c not in adp_cwe]

    return {
        "cve_id": meta.get("cveId"),
        "date_published": meta.get("datePublished"),
        "date_updated": meta.get("dateUpdated"),
        "date_reserved": meta.get("dateReserved"),
        "assigner_short_name": meta.get("assignerShortName"),
        "assigner_org_id": meta.get("assignerOrgId"),
        "cna_short_name": cna_meta.get("shortName"),
        "cna_org_id": cna_meta.get("orgId"),
        "title": cna.get("title"),
        "description": english_description(cna),
        "cwe_cna": cwe_ids(cna),
        "cwe_adp": adp_cwe,
        "cna_v40": cvss_vectors(cna, "4.0"),
        "cna_v31": cvss_vectors(cna, "3.1"),
        "adp_v40": adp_v40,
        "adp_v31": adp_v31,
        "data_version": rec.get("dataVersion"),
    }


def main(outer_path):
    outer_path = Path(outer_path)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    inner_path = extract_inner_zip(outer_path, OUT_DIR)

    rows, n_json, n_skipped, n_errors = [], 0, 0, 0
    with zipfile.ZipFile(inner_path) as inner:
        names = [n for n in inner.namelist() if n.endswith(".json") and "/CVE-" in n]
        for name in tqdm(names, desc="parsing CVE records"):
            n_json += 1
            try:
                row = extract_record(orjson.loads(inner.read(name)))
            except Exception:
                n_errors += 1
                continue
            if row is None:
                n_skipped += 1
            else:
                rows.append(row)
    inner_path.unlink()  # the inner zip is only needed while parsing

    df = pd.DataFrame(rows).sort_values("cve_id").reset_index(drop=True)
    df.to_parquet(OUT_DIR / "cve_records.parquet", index=False)

    provenance = {
        "source_file": outer_path.name,
        "source_sha256": sha256_of(outer_path),
        "json_files": n_json,
        "published_records": len(df),
        "skipped_not_published": n_skipped,
        "parse_errors": n_errors,
        "with_cna_v40": int((df["cna_v40"].str.len() > 0).sum()),
        "with_cna_v31": int((df["cna_v31"].str.len() > 0).sum()),
        "with_adp_v40": int((df["adp_v40"].str.len() > 0).sum()),
        "with_adp_v31": int((df["adp_v31"].str.len() > 0).sum()),
    }
    (OUT_DIR / "cve_records.provenance.json").write_text(json.dumps(provenance, indent=1), encoding="utf-8")
    print(json.dumps(provenance, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
