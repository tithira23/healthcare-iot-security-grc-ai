
from pathlib import Path
import csv
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)

ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = ROOT / "data" / "iot_traffic_log.csv"
OUTPUT_FILE = ROOT / "data" / "anomaly_detection_results.csv"
TRAINING_FILE = ROOT / "data" / "synthetic_training_data.csv"
REPORT_FILE = ROOT / "evidence" / "results" / "anomaly_report.txt"

FEATURES = ["heart_rate", "spo2"]
RANDOM_SEED = 42


def generate_training_data():
    rng = np.random.default_rng(RANDOM_SEED)

    # Synthetic normal telemetry for a demonstration only
    training = pd.DataFrame({
        "heart_rate": rng.normal(76, 5, 500),
        "spo2": rng.normal(98, 1, 500)
    })

    training["heart_rate"] = (
        training["heart_rate"].clip(60, 95).round(1)
    )
    training["spo2"] = (
        training["spo2"].clip(95, 100).round(1)
    )

    return training


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"MQTT traffic log not found: {INPUT_FILE}"
        )

    test_data = pd.read_csv(INPUT_FILE)

    required = FEATURES + ["asset_id", "scenario_label"]
    missing = set(required) - set(test_data.columns)

    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    if test_data.empty:
        raise ValueError("Test dataset is empty")

    if test_data[required].isna().any().any():
        raise ValueError("Missing test data values")

    if not test_data["scenario_label"].isin(
        ["Normal", "Anomaly"]
    ).all():
        raise ValueError("Unexpected scenario label")

    for feature in FEATURES:
        test_data[feature] = pd.to_numeric(
            test_data[feature], errors="raise"
        )

    training = generate_training_data()

    model = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        random_state=RANDOM_SEED
    )

    # Train on synthetic normal data only.
    model.fit(training[FEATURES])

    # Test labels are NOT supplied to the model.
    predictions = model.predict(test_data[FEATURES])
    scores = model.decision_function(test_data[FEATURES])

    test_data["predicted_label"] = [
        "Anomaly" if value == -1 else "Normal"
        for value in predictions
    ]

    test_data["anomaly_score"] = np.round(scores, 4)

    test_data["correct_prediction"] = (
        test_data["scenario_label"]
        == test_data["predicted_label"]
    )

    y_true = (
        test_data["scenario_label"] == "Anomaly"
    ).astype(int)

    y_pred = (
        test_data["predicted_label"] == "Anomaly"
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()

    precision = precision_score(
        y_true, y_pred, zero_division=0
    )
    recall = recall_score(
        y_true, y_pred, zero_division=0
    )
    f1 = f1_score(y_true, y_pred, zero_division=0)

    TRAINING_FILE.parent.mkdir(
        parents=True, exist_ok=True
    )
    REPORT_FILE.parent.mkdir(
        parents=True, exist_ok=True
    )

    training.to_csv(TRAINING_FILE, index=False)
    test_data.to_csv(OUTPUT_FILE, index=False)

    report = [
        "Healthcare IoT ML Anomaly Detection",
        "-----------------------------------",
        "Algorithm: Isolation Forest",
        f"Training samples: {len(training)}",
        f"Test messages: {len(test_data)}",
        f"Actual anomalies: {int(y_true.sum())}",
        f"Predicted anomalies: {int(y_pred.sum())}",
        "",
        "Confusion Matrix:",
        f"True Positives: {tp}",
        f"True Negatives: {tn}",
        f"False Positives: {fp}",
        f"False Negatives: {fn}",
        "",
        f"Precision: {precision:.2f}",
        f"Recall: {recall:.2f}",
        f"F1-score: {f1:.2f}",
        "",
        "Validation: PASSED",
        "",
        "Limitations:",
        "Synthetic training and test data only.",
        "Ten test messages are insufficient to",
        "establish real-world detection performance.",
        "Clinical thresholds are not validated."
    ]

    REPORT_FILE.write_text(
        "\n".join(report), encoding="utf-8"
    )

    print("\n".join(report))
    print(f"\nTraining data: {TRAINING_FILE}")
    print(f"Detection results: {OUTPUT_FILE}")
    print(f"Evaluation report: {REPORT_FILE}")


if __name__ == "__main__":
    main()
