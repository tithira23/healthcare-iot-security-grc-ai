
from pathlib import Path
from collections import Counter
import csv

ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = ROOT / "data" / "risk_register.csv"
MAPPING_FILE = ROOT / "grc" / "control_mapping.csv"
GAP_FILE = ROOT / "data" / "grc_gap_register.csv"
SUMMARY_FILE = ROOT / "evidence" / "results" / "grc_summary.txt"

# NIST CSF 2.0 mappings for this simulated assessment.
# These are illustrative, not a formal compliance audit.
CONTROLS = [
    {
        "finding": "Outdated firmware",
        "control_id": "ID.RA-05",
        "control_name": "Risk prioritisation",
        "recommendation": (
            "Review firmware vulnerabilities and prioritise "
            "approved updates or compensating controls"
        )
    },
    {
        "finding": "Firmware status requires verification",
        "control_id": "ID.AM-08",
        "control_name": "Asset lifecycle management",
        "recommendation": (
            "Verify firmware version, support status "
            "and device lifecycle records"
        )
    },
    {
        "finding": "Security monitoring disabled",
        "control_id": "DE.CM-01",
        "control_name": "Network monitoring",
        "recommendation": (
            "Assess passive monitoring or an approved "
            "alternative monitoring control"
        )
    },
    {
        "finding": "Clinical network exposure requires review",
        "control_id": "PR.IR-01",
        "control_name": "Network and environment protection",
        "recommendation": (
            "Review segmentation, allowed communication "
            "paths and firewall policy"
        )
    }
]


def read_csv(path):
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")

    with path.open(newline="", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))


def write_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    risks = read_csv(INPUT_FILE)

    if len(risks) != 20:
        raise ValueError(
            f"Expected 20 synthetic assets; found {len(risks)}"
        )

    mapping_rows = []
    gap_rows = []

    for control in CONTROLS:
        mapping_rows.append({
            "security_finding": control["finding"],
            "nist_csf_2_control": control["control_id"],
            "control_description": control["control_name"],
            "recommended_action": control["recommendation"]
        })

    for asset in risks:
        findings = [
            item.strip()
            for item in asset["security_findings"].split(";")
        ]

        for finding in findings:
            if finding == "No flagged gaps in assessed attributes":
                continue

            matched = next(
                (c for c in CONTROLS
                 if c["finding"] == finding),
                None
            )

            if matched is None:
                raise ValueError(
                    f"Unmapped security finding: {finding}"
                )

            gap_rows.append({
                "asset_id": asset["asset_id"],
                "device_type": asset["device_type"],
                "risk_score": asset["risk_score"],
                "risk_level": asset["risk_level"],
                "security_finding": finding,
                "nist_csf_2_control": matched["control_id"],
                "recommended_action": matched["recommendation"],
                "assessment_status": "Requires Review"
            })

    gap_rows.sort(
        key=lambda row: int(row["risk_score"]),
        reverse=True
    )

    write_csv(
        MAPPING_FILE,
        mapping_rows,
        [
            "security_finding",
            "nist_csf_2_control",
            "control_description",
            "recommended_action"
        ]
    )

    write_csv(
        GAP_FILE,
        gap_rows,
        [
            "asset_id",
            "device_type",
            "risk_score",
            "risk_level",
            "security_finding",
            "nist_csf_2_control",
            "recommended_action",
            "assessment_status"
        ]
    )

    counts = Counter(
        row["security_finding"] for row in gap_rows
    )

    summary = [
        "Healthcare IoT GRC Control Gap Assessment",
        "----------------------------------------",
        f"Assets reviewed: {len(risks)}",
        f"NIST CSF mappings defined: {len(CONTROLS)}",
        f"Potential control gaps: {len(gap_rows)}",
        "",
        "Findings by category:"
    ]

    for finding, count in sorted(counts.items()):
        summary.append(f"{finding}: {count}")

    summary.extend([
        "",
        "Assessment status: Requires Review",
        "Validation: PASSED",
        "",
        "Note: Findings are generated from synthetic data.",
        "They require evidence-based verification before",
        "any formal compliance or control-effectiveness claim."
    ])

    SUMMARY_FILE.parent.mkdir(
        parents=True, exist_ok=True
    )
    SUMMARY_FILE.write_text(
        "\n".join(summary), encoding="utf-8"
    )

    print("\n".join(summary))
    print(f"\nControl mapping: {MAPPING_FILE}")
    print(f"Gap register: {GAP_FILE}")
    print(f"Summary: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
