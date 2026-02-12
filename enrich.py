import pandas as pd
import httpx
import asyncio
import argparse
import re
from cvss import CVSS3, CVSS4

# --- Configuration ---
OSV_URL = "https://api.osv.dev/v1/vulns/"
RH_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/"
GH_RAW_BASE = "https://raw.githubusercontent.com/github/advisory-database/main/advisories"
HEADERS = {"User-Agent": "Triage-Crawler/6.0"}

GH_TREES = ["github-reviewed", "unreviewed", "withdrawn"]
YEAR_RANGE = range(2017, 2031)

# -------------------------------------------------------------------------
# SEVERITY STANDARDIZATION
# -------------------------------------------------------------------------

def label_standardizer(label):
    if not label:
        return None
    l = str(label).upper().strip()
    mapping = {
        "CRITICAL": "CRITICAL",
        "IMPORTANT": "IMPORTANT", "HIGH": "IMPORTANT",
        "MODERATE": "MODERATE", "MEDIUM": "MODERATE",
        "LOW": "LOW"
    }
    return mapping.get(l)

def score_to_label(score):
    try:
        val = float(score)
        if val >= 9: return "CRITICAL"
        if val >= 7: return "IMPORTANT"
        if val >= 4: return "MODERATE"
        if val > 0: return "LOW"
    except:
        pass
    return None

def extract_severity_smart(data, source):
    """Extracts severity without defaults. Returns None if nothing found."""
    # 1. Primary: Red Hat explicit severity
    if source == "RH":
        label = label_standardizer(data.get("threat_severity"))
        if label: return label

    # 2. Secondary: OSV/GH Database Specific labels
    db = data.get("database_specific", {})
    label = label_standardizer(db.get("severity"))
    if label: return label

    # 3. Tertiary: Parse CVSS arrays (Scores or Vectors)
    for entry in data.get("severity", []):
        val = entry.get("score")
        if not val: continue
        
        # Numeric score check
        if re.match(r"^\d+\.?\d*$", str(val)):
            return score_to_label(val)
        
        # Vector check
        if "CVSS:" in val:
            try:
                if "CVSS:4.0" in val: return score_to_label(CVSS4(val).score)
                return score_to_label(CVSS3(val).score)
            except: pass
    return None

# -------------------------------------------------------------------------
# NETWORK FETCHERS
# -------------------------------------------------------------------------

async def fetch_gh_repo(client, ghsa_id, published=None, modified=None):
    def extract(date):
        if not date: return None, None
        return date[:4], date[5:7]

    candidates = []
    for d in [published, modified]:
        y, m = extract(d)
        if y: candidates.append((y, m))
    
    brute = [(str(y), f"{m:02d}") for y in YEAR_RANGE for m in range(1, 13)]

    for year, month in candidates + brute:
        for tree in GH_TREES:
            url = f"{GH_RAW_BASE}/{tree}/{year}/{month}/{ghsa_id}/{ghsa_id}.json"
            try:
                r = await client.get(url, timeout=5)
                if r.status_code == 200: return r.json()
            except: continue
    return None

async def fetch_source(client, vuln_id):
    """Check Red Hat first for CVEs, then fall back to others."""
    # Try Red Hat First for CVEs
    if vuln_id.startswith("CVE-"):
        try:
            r = await client.get(f"{RH_URL}{vuln_id}.json", headers=HEADERS, timeout=5)
            if r.status_code == 200: return r.json(), "RH"
        except: pass

    # Try OSV (For GHSA, GO IDs, or CVE fallback)
    try:
        r = await client.get(f"{OSV_URL}{vuln_id}", headers=HEADERS, timeout=5)
        if r.status_code == 200:
            data = r.json()
            # If it's a GHSA, try to get the enriched GitHub JSON
            if vuln_id.startswith("GHSA-"):
                gh = await fetch_gh_repo(client, vuln_id, data.get("published"), data.get("modified"))
                if gh: return gh, "GH"
            return data, "OSV"
    except: pass

    return None, None

# -------------------------------------------------------------------------
# RECURSIVE RESOLVER
# -------------------------------------------------------------------------

async def resolve_id_recursive(client, vuln_id, visited=None, aliases_acc=None, rhsas_acc=None):
    if visited is None: visited = set()
    if aliases_acc is None: aliases_acc = set()
    if rhsas_acc is None: rhsas_acc = set()

    if vuln_id in visited or len(visited) > 20:
        return "UNKNOWN", aliases_acc, rhsas_acc

    visited.add(vuln_id)
    data, source = await fetch_source(client, vuln_id)

    if not data:
        return "UNKNOWN", aliases_acc, rhsas_acc

    # Accumulate Aliases and RHSAs
    aliases = set(data.get("aliases", []))
    aliases_acc.update(aliases)
    related = set(data.get("related", []))
    rhsas_acc.update({r for r in related if r.startswith("RHSA-")})

    # --- RESOLUTION LOGIC ---
    # 1. If we found a Red Hat record, its severity is the Final Truth.
    if source == "RH":
        sev = extract_severity_smart(data, "RH")
        if sev: return sev, aliases_acc, rhsas_acc

    # 2. If no RH record yet, pivot through CVE aliases to find one
    cve_aliases = [a for a in aliases if a.startswith("CVE-") and a != vuln_id]
    for cve_id in cve_aliases:
        sev, aliases_acc, rhsas_acc = await resolve_id_recursive(client, cve_id, visited, aliases_acc, rhsas_acc)
        if sev != "UNKNOWN":
            return sev, aliases_acc, rhsas_acc

    # 3. Last Fallback: Use OSV/GH severity only if no RH record exists in the chain
    sev = extract_severity_smart(data, source)
    return (sev or "UNKNOWN"), aliases_acc, rhsas_acc

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    df.columns = [c.strip() for c in df.columns]
    unique_ids = df["CVE"].dropna().unique().tolist()

    print(f"[*] Analyzing {len(unique_ids)} IDs with Red Hat priority...")

    results = {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        sem = asyncio.Semaphore(15)
        async def worker(vid):
            async with sem:
                return vid, await resolve_id_recursive(client, vid)

        outcomes = await asyncio.gather(*(worker(v) for v in unique_ids))
        for vid, (sev, aliases, rhsas) in outcomes:
            results[vid] = {
                "sev": sev,
                "aliases": ", ".join(sorted(aliases)),
                "rhsas": ", ".join(sorted(rhsas))
            }

    df["Triage_Severity"] = df["CVE"].map(lambda x: results.get(x, {}).get("sev", "UNKNOWN"))
    df["Triage_Aliases"] = df["CVE"].map(lambda x: results.get(x, {}).get("aliases", ""))
    df["Related_RHSA"] = df["CVE"].map(lambda x: results.get(x, {}).get("rhsas", ""))

    df.to_csv(args.output, index=False)
    
    unknown_count = (df["Triage_Severity"] == "UNKNOWN").sum()
    print(f"[*] Triage complete. Found {unknown_count} UNKNOWN values. Saved to {args.output}")

    print("\n" + "="*30)
    print("SUMMARY REPORT")
    print("="*30)
    print(f"Total Unique CVEs  : {df['CVE'].nunique()}")
    if "Image" in df.columns:
        print(f"Total Unique Images: {df['Image'].nunique()}")
    
    unknown_df = df[df["Triage_Severity"] == "UNKNOWN"][["CVE", "Triage_Aliases"]].drop_duplicates()
    
    if not unknown_df.empty:
        print("\n[!] Unique CVEs with UNKNOWN severity:")
        print(unknown_df.to_string(index=False))
    else:
        print("\nAll CVEs have been successfully triaged with a severity!")


if __name__ == "__main__":
    asyncio.run(main())