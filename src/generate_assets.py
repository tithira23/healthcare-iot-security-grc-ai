
from pathlib import Path
import csv
import ipaddress
import random

# Project configuration
random.seed(42)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = PROJECT_ROOT / "data" / "asset_inventory.csv"

DEVICE_TYPES = [
    "Patient Monitor",
    "Infusion Pump",
    "Smart Thermometer",
    "ECG Monitor",
    "Medical Imaging Device",
    "Smart Bed",
    "Environmental Sensor",
    "Medication Dispenser",
]

FIRMWARE_STATUS = [
    "Current",
    "Outdated",
    "Unknown",
]

NETWORK_ZONES = [
    "Medical-IoT",
    "Clinical-Network",
    "Facilities-IoT",
]

CRITICALITY = [
    "High",
    "Medium",
    "Low",
]

assets = []

for i in range(1, 21):
    device_type = DEVICE_TYPES[(i - 1) % len(DEVICE_TYPES)]

    asset = {
        "asset_id": f"IOT-{i:03d}",
        "device_type": device_type,
        "manufacturer": f"FictionalVendor-{(i % 4) + 1}",
        "ip_address": str(
            ipaddress.IPv4Address("192.0.2.10") + i
        ),
        "network_zone": random.choice(NETWORK_ZONES),
        "firmware_status": random.choice(FIRMWARE_STATUS),
        "criticality": random.choice(CRITICALITY),
        "asset_owner": random.choice([
            "Clinical Engineering",
            "IT Infrastructure",
            "Facilities Management",
        ]),
        "security_monitoring": random.choice([
            "Enabled",
            "Disabled",
        ]),
    }

    assets.append(asset)

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=assets[0].keys())
    writer.writeheader()
    writer.writerows(assets)

# Basic validation
asset_ids = [asset["asset_id"] for asset in assets]
ip_addresses = [asset["ip_address"] for asset in assets]

assert len(assets) == 20
assert len(set(asset_ids)) == 20
assert len(set(ip_addresses)) == 20
assert all(all(str(value).strip() for value in asset.values())
           for asset in assets)

print("Healthcare IoT Asset Inventory")
print("------------------------------")
print(f"Total assets: {len(assets)}")
print(f"Unique asset IDs: {len(set(asset_ids))}")
print(f"Unique IP addresses: {len(set(ip_addresses))}")
print("Validation: PASSED")
print(f"CSV saved to: {OUTPUT_FILE}")
