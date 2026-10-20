
from pathlib import Path
from collections import Counter
import csv
import ipaddress

# Project paths
ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = ROOT / "data" / "asset_inventory.csv"
OUTPUT_FILE = ROOT / "data" / "risk_register.csv"
SUMMARY_FILE = ROOT / "evidence" / "results" / "risk_summary.txt"

# Transparent demonstration scoring model
FIRMWARE_SCORE = {
    "Current": 0,
    "Outdated": 3,
    "Unknown": 2
}

MONITORING_SCORE = {
    "Enabled": 0,
    "Disabled": 2
}

ZONE_SCORE = {
    "Medical-IoT": 1,
    "Clinical-Network": 2,
    "Facilities-IoT": 1
}

IMPACT_SCORE = {
    "High": 3,
    "Medium": 2,
    "Low": 1
}

REQUIRED_FIELDS = [
    "asset_id",
    "device_type",
    "ip_address",
    "network_zone",
    "firmware_status",
    "criticality",
    "asset_owner",
    "security_monitoring"
]


def classify_risk(score):
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    return "Low"


def assess_asset(asset):
    firmware = asset["firmware_status"]
    monitoring = asset["security_monitoring"]
    zone = asset["network_zone"]
    criticality = asset["criticality"]

    # Validate input categories
    if firmware not in FIRMWARE_SCORE:
        raise ValueError(f"Invalid firmware status: {firmware}")

    if monitoring not in MONITORING_SCORE:
        raise ValueError(f"Invalid monitoring status: {monitoring}")

    if zone not in ZONE_SCORE:
        raise ValueError(f"Invalid network zone: {zone}")

    if criticality not in IMPACT_SCORE:
        raise ValueError(f"Invalid criticality: {criticality}")

    # Illustrative risk prioritisation score
    score = (
        FIRMWARE_SCORE[firmware]
        + MONITORING_SCORE[monitoring]
        + ZONE_SCORE[zone]
        + IMPACT_SCORE[criticality]
    )

    findings = []

    if firmware == "Outdated":
        findings.append("Outdated firmware")
    elif firmware == "Unknown":
        findings.append("Firmware status requires verification")

    if monitoring == "Disabled":
        findings.append("Security monitoring disabled")

    if zone == "Clinical-Network":
        findings.append("Clinical network exposure requires review")

    if not findings:
        findings.append("No flagged gaps in assessed attributes")

    return {
        "asset_id": asset["asset_id"],
        "device_type": asset["device_type"],
        "ip_address": asset["ip_address"],
        "criticality": criticality,
        "firmware_status": firmware,
        "security_monitoring": monitoring,
        "network_zone": zone,
        "risk_score": score,
        "risk_level": classify_risk(score),
        "security_findings": "; ".join(findings)
    }


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Asset inventory not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open(
        newline="", encoding="utf-8-sig"
    ) as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("Asset inventory has no headers")

        missing = set(REQUIRED_FIELDS) - set(reader.fieldnames)
        if missing:
            raise ValueError(f"Missing columns: {sorted(missing)}")

        assets = list(reader)

    if not assets:
        raise ValueError("Asset inventory is empty")

    ids = [asset["asset_id"] for asset in assets]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate asset IDs detected")

    for asset in assets:
        if any(not asset[field].strip()
               for field in REQUIRED_FIELDS):
            raise ValueError(
                f"Missing field in asset: {asset.get('asset_id')}"
            )
        ipaddress.ip_address(asset["ip_address"])

    results = [assess_asset(asset) for asset in assets]
    results.sort(key=lambda item: item["risk_score"],
                 reverse=True)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=results[0].keys()
        )
        writer.writeheader()
        writer.writerows(results)

    counts = Counter(item["risk_level"] for item in results)

    summary = [
        "Healthcare IoT Security Risk Assessment",
        "---------------------------------------",
        f"Total assets assessed: {len(results)}",
        f"Critical risks: {counts['Critical']}",
        f"High risks: {counts['High']}",
        f"Medium risks: {counts['Medium']}",
        f"Low risks: {counts['Low']}",
        "Validation: PASSED",
        "",
        "Top 5 prioritised assets:"
    ]

    for item in results[:5]:
        summary.append(
            f"{item['asset_id']} | "
            f"Score: {item['risk_score']} | "
            f"{item['risk_level']} | "
            f"{item['security_findings']}"
        )

    SUMMARY_FILE.write_text(
        "\n".join(summary), encoding="utf-8"
    )

    print("\n".join(summary))
    print(f"\nRisk register: {OUTPUT_FILE}")
    print(f"Summary report: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
