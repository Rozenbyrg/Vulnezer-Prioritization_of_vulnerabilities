import sys
import os
import io
import csv
import json
import argparse
import time
import zipfile
import requests
from dotenv import load_dotenv

load_dotenv()
nvd_key = os.getenv("NVD_API_KEY")
vulncheck_key = os.getenv("VULNCHECK_API_KEY")


class NvdApiClient:
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {}
        if api_key:
            self.headers["apiKey"] = api_key

    def get_cvss_score(self, cve_id):
        try:
            response = requests.get(
                self.base_url,
                headers=self.headers,
                params={"cveId": cve_id},
                timeout=30
            )
            response.raise_for_status()

            # This delay value can be changed to a higher value
            time.sleep(0.6)

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                return None, None

            cve_info = vulnerabilities[0]["cve"]
            metrics = cve_info.get("metrics", {})

            version_priority = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
            version_names = {
                "cvssMetricV40": "4.0",
                "cvssMetricV31": "3.1",
                "cvssMetricV30": "3.0",
                "cvssMetricV2": "2.0"
            }

            for version_key in version_priority:
                if version_key in metrics and metrics[version_key]:
                    metric_data = metrics[version_key]
                    if not isinstance(metric_data, list):
                        continue

                    nvd_result = None
                    cna_result = None

                    for entry in metric_data:
                        try:
                            if "cvssData" not in entry or "baseScore" not in entry["cvssData"]:
                                continue

                            score = entry["cvssData"]["baseScore"]
                            source = entry.get("source", "").lower()
                            ver = version_names[version_key]

                            if "nvd.nist.gov" in source:
                                nvd_result = (score, ver)
                            elif not cna_result:
                                cna_result = (score, ver)
                        except (KeyError, TypeError):
                            continue

                    if nvd_result:
                        return nvd_result
                    elif cna_result:
                        return cna_result

            return None, None

        except Exception as e:
            print(f"Error getting CVSS for {cve_id}: {e}", file=sys.stderr)
            return None, None


class EpssApi:
    def __init__(self):
        self.url = "https://api.first.org/data/v1/epss"

    def get_epss_score(self, cve_id):
        try:
            resp = requests.get(self.url, params={"cve": cve_id}, timeout=15)
            resp.raise_for_status()

            result = resp.json().get("data")
            if isinstance(result, dict) and cve_id in result:
                return float(result[cve_id].get("epss", 0))
            elif isinstance(result, list):
                for item in result:
                    if item.get("cve") == cve_id:
                        return float(item.get("epss", 0))
            return None
        except:
            return None


class KevData:
    def __init__(self, api_key):
        self.feed_url = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
        self.headers = {
            "accept": "application/json",
            "authorization": f"Bearer {api_key}"
        }

    def load_kev_cves(self):
        """All KEV will be placed into a set for fast lookup"""
        try:
            resp = requests.get(self.feed_url, headers=self.headers, timeout=30)
            resp.raise_for_status()
            feed_data = resp.json()

            entries = []
            if isinstance(feed_data, dict) and feed_data.get("data"):
                zip_url = feed_data["data"][0]["url"]
                zip_resp = requests.get(zip_url, timeout=30)
                zip_resp.raise_for_status()

                with zipfile.ZipFile(io.BytesIO(zip_resp.content)) as zf:
                    with zf.open(zf.namelist()[0]) as f:
                        entries = json.load(f)
            elif isinstance(feed_data, list):
                entries = feed_data
            else:
                return {}

            kev_set = {}
            for entry in entries:
                cve_data = entry.get("cve", [])
                if isinstance(cve_data, str):
                    kev_set[cve_data] = True
                elif isinstance(cve_data, list):
                    for cve in cve_data:
                        kev_set[cve] = True

            return kev_set
        except Exception as e:
            print(f"KEV error: {e}", file=sys.stderr)
            return {}


def calc_risk_score(cvss_val, epss_val, is_kev):
    cvss = cvss_val if cvss_val is not None else 0.0
    epss = epss_val if epss_val is not None else 0.0

    if is_kev:
        risk = 0.5 + 0.3 * epss + 0.2 * (cvss / 10)
        if risk >= 0.7 and cvss >= 7:
            priority = "Critical"
        else:
            priority = "High"
    else:
        risk = 0.2 + 0.3 * epss + 0.2 * (cvss / 10)
        if epss >= 0.1 and cvss >= 7:
            priority = "Medium"
        elif epss >= 0.1 and cvss < 7:
            priority = "Low"
        elif epss < 0.1 and cvss >= 7:
            priority = "Medium"
        else:
            priority = "Low"

    return round(risk, 4), priority

def assign_scores_within_categories(cve_results):
    categories = {"Critical": [], "High": [], "Medium": [], "Low": []}

    for result in cve_results:
        cat = result["Priority"]
        categories[cat].append(result)

    final_results = []

    for category, items in categories.items():
        items.sort(key=lambda x: x["Risk"], reverse=True)
        max_items = min(len(items), 10000)

        for idx, item in enumerate(items[:max_items]):
            item["Priority_Score"] = idx + 1
            item["Within_Capacity"] = True
            final_results.append(item)

        for item in items[max_items:]:
            item["Priority_Score"] = None
            item["Within_Capacity"] = False
            final_results.append(item)

    return final_results


def load_cves_from_file(filepath, col_name="CVE"):
    cve_list = []
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if col_name not in reader.fieldnames:
            raise ValueError(f"Column '{col_name}' not found in file")
        for row in reader:
            cve_id = row[col_name].strip()
            if cve_id:
                cve_list.append(cve_id)
    return cve_list


def main():
    parser = argparse.ArgumentParser(description="Vulnezer made by Pavlo")
    parser.add_argument("cves", nargs="*", help="CVE IDs to analyze")
    parser.add_argument("-i", "--input-csv", help="Input CSV file containing CVE IDs")
    parser.add_argument("--column-name", default="CVE", help="CSV column name for CVE IDs (default: CVE)")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table",
                        help="Output format: table (human-readable), csv (export), json (automation)")
    parser.add_argument("--show-all", action="store_true", help="Include CVEs beyond capacity limits")
    args = parser.parse_args()

    if args.input_csv and args.cves:
        print("Error: Please provide either CVE ID or CSV file, you can't provide both")
        return
    if not args.input_csv and not args.cves:
        print("Error: Must provide CVE ID or CSV file")
        return

    missing_keys = []
    if not nvd_key:
        missing_keys.append("NVD_API_KEY")
    if not vulncheck_key:
        missing_keys.append("VULNCHECK_API_KEY")
    if missing_keys:
        print(f"Missing environment variables: {', '.join(missing_keys)}")
        return

    if args.input_csv:
        cves_to_process = load_cves_from_file(args.input_csv, args.column_name)
    else:
        cves_to_process = args.cves

    nvd_client = NvdApiClient(api_key=nvd_key)
    epss_client = EpssApi()
    kev_client = KevData(api_key=vulncheck_key)
    print("Loading KEV data...", file=sys.stderr)
    kev_lookup = kev_client.load_kev_cves()
    results = []
    total = len(cves_to_process)

    for i, cve in enumerate(cves_to_process):
        if i % 10 == 0:
            print(f"Processing {i}/{total}...", file=sys.stderr)
        try:
            cvss_score, cvss_version = nvd_client.get_cvss_score(cve)
            epss_score = epss_client.get_epss_score(cve)
            in_kev = kev_lookup.get(cve, False)

            risk_score, priority_cat = calc_risk_score(cvss_score, epss_score, in_kev)

            warning_msg = ""
            if cvss_score is not None:
                if cvss_score > 9:
                    warning_msg = "PCI DSS. Remediation required within 30 days of discovery"
                elif cvss_score >= 4:
                    warning_msg = "PCI DSS. Will fail in case of external audit"
            if in_kev and not warning_msg:
                warning_msg = "Remediation recommended within 30 days"

            results.append({
                "CVE": cve,
                "CVSS Score": cvss_score,
                "CVSS Ver": cvss_version,
                "EPSS": epss_score,
                "KEV": "Yes" if in_kev else "No",
                "Risk": risk_score,
                "Priority": priority_cat,
                "Warning": warning_msg
            })

        except Exception as e:
            print(f"Failed to process {cve}: {e}", file=sys.stderr)
            results.append({
                "CVE": cve,
                "CVSS Score": None,
                "CVSS Ver": None,
                "EPSS": None,
                "KEV": "No",
                "Risk": 0.0,
                "Priority": "Low",
                "Warning": ""
            })

    results = assign_scores_within_categories(results)

    if not args.show_all:
        results = [r for r in results if r["Within_Capacity"]]

    priority_nums = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    results.sort(key=lambda x: (
        priority_nums.get(x["Priority"], 5),
        x["Priority_Score"] if x["Priority_Score"] is not None else 9999
    ))

    if args.format == "json":
        print(json.dumps(results, indent=2))
    elif args.format == "csv":
        headers = ["CVE", "CVSS_Score", "CVSS_Ver", "EPSS", "KEV", "Risk", "Priority", "Priority_Score", "Warning"]
        print(",".join(headers))
        for row in results:
            values = []
            for field in ["CVE", "CVSS Score", "CVSS Ver", "EPSS", "KEV", "Risk", "Priority", "Priority_Score", "Warning"]:
                val = row[field]
                values.append(str(val) if val is not None else "")
            print(",".join(values))
    else:
        print("| CVE            | CVSS | Ver | EPSS   | KEV | Risk   | Priority | Score | Warning                                         |")
        print("| -------------- | ---- | --- | ------ | --- | ------ | -------- | ----- | ----------------------------------------------- |")
        for r in results:
            cvss_display = "N/A" if r["CVSS Score"] is None else f"{r['CVSS Score']:.1f}"
            epss_display = "N/A" if r["EPSS"] is None else f"{r['EPSS']:.4f}"
            ver_display = r["CVSS Ver"] or "N/A"
            score_display = str(r["Priority_Score"]) if r["Priority_Score"] is not None else "N/A"
            warning_text = r["Warning"] or ""
            print(f"| {r['CVE']} | {cvss_display:<4} | {ver_display:<3} | "
                  f"{epss_display:<6} | {r['KEV']:<3} | {r['Risk']:<6} | "
                  f"{r['Priority']:<8} | {score_display:<5} | {warning_text:<47} |")

    print("\nSummary:", file=sys.stderr)
    category_totals = {}
    capacity_counts = {}
    for r in results:
        cat = r["Priority"]
        category_totals[cat] = category_totals.get(cat, 0) + 1
        if r["Within_Capacity"]:
            capacity_counts[cat] = capacity_counts.get(cat, 0) + 1
    for cat in ["Critical", "High", "Medium", "Low"]:
        total_count = category_totals.get(cat, 0)
        within_capacity = capacity_counts.get(cat, 0)
        if total_count > 10000:
            print(f"{cat}: {within_capacity}/{total_count} (exceeded capacity)", file=sys.stderr)
        else:
            print(f"{cat}: {within_capacity}/{total_count}", file=sys.stderr)


if __name__ == "__main__":
    main()
