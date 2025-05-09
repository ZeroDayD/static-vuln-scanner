import re
import os
import json
import yaml
from pathlib import Path

SARIF_TEMPLATE = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "StaticVulnScanner",
                    "rules": []
                }
            },
            "results": []
        }
    ]
}

SUPPORTED_EXTENSIONS = ['.js', '.py', '.php']


def load_patterns(file_path="patterns.yaml"):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)


def scan_file(file_path, patterns):
    results = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for lineno, line in enumerate(lines, start=1):
        for rule in patterns:
            if re.search(rule["regex"], line):
                print(f"[!] Match: {rule['id']} in {file_path} at line {lineno}: {line.strip()}")
                results.append({
                    "rule_id": rule["id"],
                    "message": rule["description"],
                    "file": str(file_path),
                    "line": lineno
                })
    return results


def to_sarif(results, patterns):
    sarif = json.loads(json.dumps(SARIF_TEMPLATE))
    added_rules = set()

    for result in results:
        rule_id = result["rule_id"]
        if rule_id not in added_rules:
            rule_info = next((r for r in patterns if r["id"] == rule_id), None)
            if rule_info:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": rule_info["description"],
                    "shortDescription": {"text": rule_info["description"]}
                })
                added_rules.add(rule_id)

        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "message": {"text": result["message"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": result["file"]},
                        "region": {"startLine": result["line"]}
                    }
                }
            ]
        })
    return sarif


def main():
    patterns = load_patterns()
    all_results = []
    for root, _, files in os.walk("."):
        for file in files:
            if Path(file).suffix in SUPPORTED_EXTENSIONS:
                file_path = Path(root) / file
                print(f"Scanning: {file_path}")
                all_results.extend(scan_file(file_path, patterns))

    sarif_data = to_sarif(all_results, patterns)
    with open("results.sarif", "w") as out:
        json.dump(sarif_data, out, indent=2)

    if all_results:
        print(f"\nFound {len(all_results)} issue(s). See details above or in results.sarif")
        exit(1)
    else:
        print("No issues found")
        exit(0)


if __name__ == "__main__":
    main()
