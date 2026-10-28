"""List all commits of the CISA Vulnrichment repository with their dates.

Keeps a commits-only clone (no trees, no file contents; a few MB) in data/external/vulnrichment_commits.git
and writes data/vulnrichment_commits.tsv: sha, committer date (UTC, ISO 8601), tree sha, sorted by date.
Running it again fetches new commits; the HEAD commit and the number of commits go to
data/vulnrichment_commits.meta.json.
"""

import json
import subprocess
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / "data" / "external" / "vulnrichment_commits.git"
OUT = ROOT / "data" / "vulnrichment_commits.tsv"
URL = "https://github.com/cisagov/vulnrichment.git"


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def main():
    if REPO.exists():
        git("-C", str(REPO), "fetch", "-q", "origin", "+refs/heads/*:refs/heads/*")
    else:
        REPO.parent.mkdir(parents=True, exist_ok=True)
        git("clone", "-q", "--bare", "--filter=tree:0", URL, str(REPO))
    log = git("-C", str(REPO), "log", "--format=%H\t%cI\t%T", "HEAD")
    df = pd.DataFrame([l.split("\t") for l in log.splitlines() if l], columns=["sha", "date", "tree"])
    df["date"] = pd.to_datetime(df.date, utc=True)
    df = df.sort_values("date", kind="stable").reset_index(drop=True)
    df.assign(date=df.date.dt.strftime("%Y-%m-%dT%H:%M:%SZ")).to_csv(OUT, sep="\t", index=False)
    meta = {"head": git("-C", str(REPO), "rev-parse", "HEAD").strip(), "commits": len(df),
            "first": str(df.date.iloc[0]), "last": str(df.date.iloc[-1]), "distinct_trees": int(df.tree.nunique())}
    OUT.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print(json.dumps(meta, indent=1))


if __name__ == "__main__":
    main()
