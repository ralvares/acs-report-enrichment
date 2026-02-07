import pandas as pd
import httpx
import asyncio
import argparse
import re
from cvss import CVSS3, CVSS4

OSV_URL = "https://api.osv.dev/v1/vulns/"
RH_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/"
GH_RAW_BASE = "https://raw.githubusercontent.com/github/advisory-database/main/advisories"

HEADERS = {"User-Agent": "Crawler-Tool/5.0"}

GH_TREES = ["github-reviewed", "unreviewed", "withdrawn"]
YEAR_RANGE = range(2017, 2031)

# ---------------- Severity ----------------

def label_standardizer(label):
    if not label:
        return None

    l = str(label).upper().strip()

    if l == "CRITICAL":
        return "CRITICAL"
    if l in ["HIGH", "IMPORTANT"]:
        return "IMPORTANT"
    if l in ["MEDIUM", "MODERATE"]:
        return "MODERATE"
    if l == "LOW":
        return "LOW"

    return None


def score_to_label(score):
    try:
        val = float(score)
        if val >= 9:
            return "CRITICAL"
        if val >= 7:
            return "IMPORTANT"
        if val >= 4:
            return "MODERATE"
        if val > 0:
            return "LOW"
    except:
        pass
    return None


def extract_severity_smart(data, source):

    if source == "RH":
        label = label_standardizer(data.get("threat_severity"))
        if label:
            return label

    # GH database_specific severity
    db = data.get("database_specific", {})
    label = label_standardizer(db.get("severity"))
    if label:
        return label

    # GH severity array
    for entry in data.get("severity", []):
        val = entry.get("score")

        if not val:
            continue

        if re.match(r"^\d+\.?\d*$", str(val)):
            return score_to_label(val)

        if "CVSS:" in val:
            try:
                if "CVSS:4.0" in val:
                    return score_to_label(CVSS4(val).score)
                return score_to_label(CVSS3(val).score)
            except:
                pass

    return None


# ---------------- GH RAW FETCH ----------------

async def fetch_gh_repo(client, ghsa_id, published=None, modified=None):

    def extract(date):
        if not date:
            return None, None
        return date[:4], date[5:7]

    # ----- Try OSV hinted dates first -----
    date_candidates = []
    for d in [published, modified]:
        y, m = extract(d)
        if y:
            date_candidates.append((y, m))

    # ----- Add brute fallback -----
    brute = [(str(y), f"{m:02d}") for y in YEAR_RANGE for m in range(1, 13)]

    for year, month in date_candidates + brute:
        for tree in GH_TREES:

            url = f"{GH_RAW_BASE}/{tree}/{year}/{month}/{ghsa_id}/{ghsa_id}.json"

            try:
                r = await client.get(url, timeout=10)
                if r.status_code == 200:
                    return r.json()
            except httpx.HTTPError:
                continue

    return None


# ---------------- SOURCE FETCH ----------------

async def fetch_source(client, vuln_id):

    # ---------- GHSA ----------
    if vuln_id.startswith("GHSA-"):

        # Try OSV only to get metadata (date hints)
        osv_meta = None
        try:
            r = await client.get(f"{OSV_URL}{vuln_id}", headers=HEADERS, timeout=10)
            if r.status_code == 200:
                osv_meta = r.json()
        except httpx.HTTPError:
            pass

        gh = await fetch_gh_repo(
            client,
            vuln_id,
            osv_meta.get("published") if osv_meta else None,
            osv_meta.get("modified") if osv_meta else None
        )

        if gh:
            return gh, "GH"

        if osv_meta:
            return osv_meta, "OSV"

        return None, None

    # ---------- CVE ----------
    if vuln_id.startswith("CVE-"):

        try:
            r = await client.get(f"{RH_URL}{vuln_id}.json", headers=HEADERS, timeout=10)
            if r.status_code == 200:
                return r.json(), "RH"
        except httpx.HTTPError:
            pass

        try:
            r = await client.get(f"{OSV_URL}{vuln_id}", headers=HEADERS, timeout=10)
            if r.status_code == 200:
                return r.json(), "OSV"
        except httpx.HTTPError:
            pass

        return None, None

    # ---------- Fallback OSV ----------
    try:
        r = await client.get(f"{OSV_URL}{vuln_id}", headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json(), "OSV"
    except httpx.HTTPError:
        pass

    return None, None


# ---------------- Alias Handling ----------------

def sort_alias_priority(aliases):
    return sorted(
        aliases,
        key=lambda x: (
            not x.startswith("GHSA-"),
            not x.startswith("CVE-")
        )
    )


# ---------------- Recursive Resolver ----------------

async def resolve_id_recursive(client, vuln_id, visited=None, aliases_acc=None, rhsas_acc=None):

    if visited is None:
        visited = set()

    if aliases_acc is None:
        aliases_acc = set()

    if rhsas_acc is None:
        rhsas_acc = set()

    if vuln_id in visited or len(visited) > 40:
        return "UNKNOWN", aliases_acc, rhsas_acc

    visited.add(vuln_id)

    data, source = await fetch_source(client, vuln_id)

    if not data:
        return "UNKNOWN", aliases_acc, rhsas_acc

    aliases = set(data.get("aliases", []))
    aliases_acc.update(aliases)

    related = set(data.get("related", []))
    rhsas_acc.update({r for r in related if r.startswith("RHSA-")})

    sev = extract_severity_smart(data, source)
    if sev:
        return sev, aliases_acc, rhsas_acc

    for alias in sort_alias_priority(aliases):
        sev, aliases_acc, rhsas_acc = await resolve_id_recursive(
            client, alias, visited, aliases_acc, rhsas_acc
        )
        if sev != "UNKNOWN":
            return sev, aliases_acc, rhsas_acc

    return "UNKNOWN", aliases_acc, rhsas_acc


# ---------------- Main ----------------

async def main(input_path, output_path):

    df = pd.read_csv(input_path)
    df.columns = [c.strip() for c in df.columns]

    unique_ids = df["CVE"].dropna().unique().tolist()

    results = {}

    async with httpx.AsyncClient(follow_redirects=True) as client:

        sem = asyncio.Semaphore(10)

        async def worker(vid):
            async with sem:
                return await resolve_id_recursive(client, vid)

        outcomes = await asyncio.gather(*(worker(v) for v in unique_ids))

        for vid, (sev, aliases, rhsas) in zip(unique_ids, outcomes):
            results[vid] = {
                "sev": sev,
                "aliases": ", ".join(sorted(aliases)),
                "rhsas": ", ".join(sorted(rhsas))
            }

    df["OSV_Severity_Enriched"] = df["CVE"].map(lambda x: results.get(x, {}).get("sev", "UNKNOWN"))
    df["OSV_Aliases"] = df["CVE"].map(lambda x: results.get(x, {}).get("aliases", ""))
    df["OSV_Related_RHSA"] = df["CVE"].map(lambda x: results.get(x, {}).get("rhsas", ""))

    df.to_csv(output_path, index=False)


# ---------------- CLI ----------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)

    args = parser.parse_args()

    asyncio.run(main(args.input, args.output))
