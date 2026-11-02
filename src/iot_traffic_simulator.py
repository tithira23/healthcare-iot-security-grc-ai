
from pathlib import Path
from datetime import datetime, timezone
import csv
import json
import time

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = ROOT / "data" / "iot_traffic_log.csv"

BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "healthcare/iot/telemetry"

# Synthetic devices only. No real patient data.
DEVICES = [
    ("IOT-001", "Patient Monitor"),
    ("IOT-002", "Infusion Pump"),
    ("IOT-004", "ECG Monitor"),
]

# Normal and intentionally anomalous test scenarios.
SCENARIOS = [
    ("Normal", 75, 98),
    ("Normal", 78, 97),
    ("Normal", 72, 99),
    ("Normal", 80, 98),
    ("Anomaly", 145, 82),
    ("Normal", 76, 98),
    ("Normal", 74, 99),
    ("Anomaly", 155, 79),
    ("Normal", 77, 97),
    ("Normal", 73, 98),
]


def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="healthcare-iot-simulator"
    )

    try:
        client.connect(BROKER, PORT, keepalive=60)
        client.loop_start()
    except OSError as error:
        raise SystemExit(
            f"MQTT connection failed: {error}\n"
            "Check that the local Mosquitto broker is running."
        )

    rows = []

    try:
        for index, (status, heart_rate, spo2) in enumerate(
            SCENARIOS, start=1
        ):
            device_id, device_type = DEVICES[
                (index - 1) % len(DEVICES)
            ]

            message = {
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "asset_id": device_id,
                "device_type": device_type,
                "heart_rate": heart_rate,
                "spo2": spo2,
                "scenario_label": status
            }

            payload = json.dumps(message)

            result = client.publish(
                TOPIC, payload, qos=1
            )
            result.wait_for_publish(timeout=10)

            if not result.is_published():
                raise RuntimeError(
                    f"Message {index} was not published"
                )

            rows.append(message)

            print(
                f"{index:02d} | {device_id} | "
                f"HR={heart_rate} | SpO2={spo2} | "
                f"{status}"
            )

            time.sleep(0.5)

    finally:
        client.disconnect()
        client.loop_stop()

    if len(rows) != 10:
        raise ValueError("Unexpected message count")

    if sum(
        row["scenario_label"] == "Anomaly"
        for row in rows
    ) != 2:
        raise ValueError("Unexpected anomaly count")

    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=rows[0].keys()
        )
        writer.writeheader()
        writer.writerows(rows)

    print("\nHealthcare IoT MQTT Simulation")
    print("------------------------------")
    print(f"Messages published: {len(rows)}")
    print("Normal messages: 8")
    print("Anomalous test messages: 2")
    print("Validation: PASSED")
    print(f"Traffic log: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

