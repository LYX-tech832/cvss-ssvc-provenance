"""Vulnerability type and product type, derived from CVE record fields only (no CVSS, no SSVC).

Vulnerability type: the record's CWE identifiers (CNA first; ADP if the CNA gives none). If any is one of the 25 types
below, the first of them in this list is used; otherwise "other CWE"; no CWE at all gives "unknown". The list is ordered
by frequency among records with a CISA SSVC decision in the 2026-09-25 snapshot.

Product type, first matching rule:
  1. CPE part "o"                                                          -> operating system
  2. CPE part "h"                                                          -> hardware / firmware
  3. collectionURL contains wordpress.org, or the description mentions
     "plugin for WordPress" / "WordPress plugin"                           -> WordPress plugin
  4. collectionURL points to a package registry (npm, PyPI, Maven, RubyGems,
     NuGet, Packagist, crates.io, Go modules, GitHub) or a packageName exists -> open-source package
  5. CPE part "a"                                                          -> application
  6. otherwise                                                             -> unknown
"""

import re

TOP_CWES = ["CWE-79", "CWE-89", "CWE-862", "CWE-284", "CWE-352", "CWE-22", "CWE-74", "CWE-787", "CWE-20", "CWE-125",
            "CWE-416", "CWE-200", "CWE-94", "CWE-78", "CWE-121", "CWE-119", "CWE-120", "CWE-918", "CWE-434", "CWE-863",
            "CWE-122", "CWE-77", "CWE-400", "CWE-306", "CWE-502"]
_RANK = {c: i for i, c in enumerate(TOP_CWES)}
_WP_DESC = re.compile(r"plugin for wordpress|wordpress plugin", re.I)
_REGISTRY = re.compile(r"npmjs|pypi\.org|maven|rubygems|nuget|packagist|crates\.io|pkg\.go\.dev|proxy\.golang|github\.com", re.I)


def vuln_type(cwe_cna, cwe_adp):
    field = cwe_cna if isinstance(cwe_cna, str) and cwe_cna else cwe_adp
    if not isinstance(field, str) or not field:
        return "unknown"
    ids = [c for c in field.split("|") if c in _RANK]
    return min(ids, key=_RANK.get) if ids else "other CWE"


def product_type(cpe_parts, collection_urls, has_package_name, description):
    parts = cpe_parts if isinstance(cpe_parts, str) else ""
    urls = collection_urls if isinstance(collection_urls, str) else ""
    if "o" in parts:
        return "operating system"
    if "h" in parts:
        return "hardware / firmware"
    if "wordpress.org" in urls.lower() or (isinstance(description, str) and _WP_DESC.search(description)):
        return "WordPress plugin"
    if _REGISTRY.search(urls) or bool(has_package_name):
        return "open-source package"
    if "a" in parts:
        return "application"
    return "unknown"
