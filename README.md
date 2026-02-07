### 1. Prerequisites

Ensure you have **Python 3.8 or higher** installed on your system.

### 2. Install Dependencies

You need to install the libraries used for data handling, web requests, and CVSS math. Run the following command in your terminal:

```bash
pip install pandas httpx cvss

```

### 3. Prepare Your Input File

The script expects a **CSV file** as input.

* It must have a column named **`CVE`**.
* This column can contain standard CVE IDs (e.g., `CVE-2024-1234`), GitHub Advisory IDs (e.g., `GHSA-abcd-1234`), or Go IDs.

### 4. How to Use It

1. Save the code provided above into a file named `enrich.py`.
2. Open your terminal/command prompt.
3. Run the script using the `-i` (input) and `-o` (output) flags:

```bash
python enrich.py -i your_report.csv -o enriched_results.csv

```

### 5. What Happens Under the Hood?

The script performs an "aggressive crawl" to find missing data. If it can't find a severity rating on the first try, it follows "aliases" (linked IDs) across different databases.

### 6. Understanding the Output

The script will generate a new CSV file with three extra columns:

* **`OSV_Severity_Enriched`**: The standardized severity (CRITICAL, IMPORTANT, MODERATE, or LOW). It calculates this even if only a "vector string" is found.
* **`OSV_Aliases`**: All other IDs related to this vulnerability (cross-referencing GHSA and CVE).
* **`OSV_Related_RHSA`**: Specifically filters and lists related **Red Hat Security Advisories**, which are useful for OpenShift/RHEL users to find official patches.

---
