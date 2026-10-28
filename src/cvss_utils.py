"""Parsing, conversion and scoring of CVSS v3.1 / v4.0 base vectors.

Only the base metrics are kept; threat, environmental and supplemental metrics in a vector (for example E:P or CR:H)
are ignored. Metric values as defined in FIRST's specifications:
  v3.1  https://www.first.org/cvss/v3.1/specification-document
  v4.0  https://www.first.org/cvss/v4.0/specification-document

Rule R converts a v3.1 base vector into a v4.0 base vector:
  AV, AC and PR copied; AT = N; UI: N -> N, R -> P; VC/VI/VA = C/I/A;
  SC/SI/SA = C/I/A if S:C, otherwise N.
"""

import numpy as np
from cvss import CVSS4

V31_METRICS = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "R"],
    "S": ["U", "C"],
    "C": ["H", "L", "N"],
    "I": ["H", "L", "N"],
    "A": ["H", "L", "N"],
}

V40_METRICS = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "AT": ["N", "P"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "P", "A"],
    "VC": ["H", "L", "N"],
    "VI": ["H", "L", "N"],
    "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"],
    "SI": ["H", "L", "N"],
    "SA": ["H", "L", "N"],
}

M31 = list(V31_METRICS)
M40 = list(V40_METRICS)
PREFIX = {"3.1": "CVSS:3.1/", "4.0": "CVSS:4.0/"}
METRICS = {"3.1": V31_METRICS, "4.0": V40_METRICS}
SEVERITY_ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def parse_vector(vector, version):
    """Parse a vector string into {metric: value}.

    Returns None if the string is malformed, lacks a base metric or has an invalid value (the caller then drops the label).
    """
    if not isinstance(vector, str) or not vector.startswith(PREFIX[version]):
        return None
    allowed = METRICS[version]
    parsed = {}
    for part in vector[len(PREFIX[version]):].split("/"):
        key, sep, value = part.partition(":")
        if not sep:
            return None
        if key in allowed:
            if value not in allowed[key] or key in parsed:
                return None
            parsed[key] = value
    if set(parsed) != set(allowed):
        return None
    return parsed


def base_vector(parsed, version):
    """Rebuild a vector string with the base metrics only, in the order of the specification (for de-duplication and comparison)."""
    return PREFIX[version] + "/".join(f"{k}:{parsed[k]}" for k in METRICS[version])


def rule_convert(v31):
    """Rule R: v3.1 base metrics (dict) -> v4.0 base metrics (dict)."""
    sub = {"SC": v31["C"], "SI": v31["I"], "SA": v31["A"]} if v31["S"] == "C" else {"SC": "N", "SI": "N", "SA": "N"}
    return {
        "AV": v31["AV"], "AC": v31["AC"], "AT": "N", "PR": v31["PR"],
        "UI": "N" if v31["UI"] == "N" else "P",
        "VC": v31["C"], "VI": v31["I"], "VA": v31["A"], **sub,
    }


def to_vector(metrics):
    """{v4.0 metric: value} (or a row with these keys) -> v4.0 vector string."""
    return "CVSS:4.0/" + "/".join(f"{k}:{metrics[k]}" for k in M40)


_score_cache = {}


def v4_score(vec):
    """(CVSS-B score, severity band) of a v4.0 vector; the band follows FIRST's qualitative ranges as given by the cvss library."""
    if vec not in _score_cache:
        try:
            c = CVSS4(vec)
            _score_cache[vec] = (float(c.base_score), c.severity)
        except Exception:
            _score_cache[vec] = (np.nan, None)
    return _score_cache[vec]
