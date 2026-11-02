
from pathlib import Path

import pandas as pd
import streamlit as st


# ==================================================
# 1. PROJECT CONFIGURATION
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
GRC_DIR = PROJECT_ROOT / "grc"

st.set_page_config(
    page_title="Healthcare IoT Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)


# ==================================================
# 2. LOAD PROJECT DATASETS
# ==================================================

@st.cache_data
def load_data():
    files = {
        "assets": DATA_DIR / "asset_inventory.csv",
        "risks": DATA_DIR / "risk_register.csv",
        "grc": DATA_DIR / "grc_gap_register.csv",
        "anomalies": DATA_DIR / "anomaly_detection_results.csv",
        "controls": GRC_DIR / "control_mapping.csv",
    }

    datasets = {}

    for name, path in files.items():
        if not path.is_file():
            raise FileNotFoundError(
                f"Missing dataset: {path}"
            )

        datasets[name] = pd.read_csv(path)

    return datasets


try:
    data = load_data()

except (FileNotFoundError, pd.errors.ParserError) as error:
    st.error(f"Unable to load project datasets: {error}")
    st.stop()


assets = data["assets"]
risks = data["risks"]
grc = data["grc"]
anomalies = data["anomalies"]
controls = data["controls"]


# ==================================================
# 3. DATA PREPARATION
# ==================================================

# Standard cybersecurity risk severity order
RISK_ORDER = ["Critical", "High", "Medium", "Low"]

risk_counts = (
    risks["risk_level"]
    .astype(str)
    .str.strip()
    .str.title()
    .value_counts()
)

risk_distribution = risk_counts.reindex(
    RISK_ORDER,
    fill_value=0
)

# Explicitly ordered chart dataset
risk_chart_data = (
    risk_distribution
    .rename_axis("Risk Level")
    .reset_index(name="Asset Count")
)

# Interpret prediction labels.
# Isolation Forest convention:
# -1 = anomaly, 1 = normal.
# Text labels are also supported.

def classify_prediction(value):
    label = str(value).strip().lower()

    if label in ("-1", "anomaly", "anomalous"):
        return "Anomaly"

    if label in ("1", "normal"):
        return "Normal"

    return "Unknown"


anomalies = anomalies.copy()

anomalies["detection_status"] = (
    anomalies["predicted_label"]
    .apply(classify_prediction)
)

detected_count = int(
    (anomalies["detection_status"] == "Anomaly").sum()
)

normal_count = int(
    (anomalies["detection_status"] == "Normal").sum()
)

unknown_count = int(
    (anomalies["detection_status"] == "Unknown").sum()
)


# ==================================================
# 4. DASHBOARD HEADER AND KPIs
# ==================================================

st.title("🛡️ Healthcare IoT Security Dashboard")

st.caption(
    "Synthetic Healthcare IoT Security Laboratory | "
    "Asset Management • Risk Assessment • "
    "NIST CSF 2.0 • ML Anomaly Detection"
)

st.info(
    "Educational simulation only. Findings do not "
    "represent real-world incidents, clinical risks "
    "or confirmed regulatory noncompliance."
)

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Total IoT Assets",
        len(assets)
    )

with col2:
    st.metric(
        "High-Risk Assets",
        int(risk_distribution["High"])
    )

with col3:
    st.metric(
        "GRC Findings",
        len(grc)
    )

with col4:
    st.metric(
        "Detected Anomalies",
        detected_count if unknown_count == 0 else "Check labels"
    )

st.divider()


# ==================================================
# 5. DASHBOARD TABS
# ==================================================

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "📦 Asset Inventory",
        "⚠️ Risk Assessment",
        "📋 GRC Assessment",
        "🤖 ML Anomaly Detection",
    ]
)


# ==================================================
# TAB 1 — ASSET INVENTORY
# ==================================================

with tab1:

    st.subheader("Healthcare IoT Asset Inventory")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Device Type Distribution**")

        device_counts = (
            assets["device_type"]
            .value_counts()
        )

        st.bar_chart(device_counts)

    with col2:
        st.markdown("**Firmware Status Distribution**")

        firmware_counts = (
            assets["firmware_status"]
            .value_counts()
        )

        st.bar_chart(firmware_counts)

    st.markdown("**Asset Inventory Details**")

    device_options = sorted(
        assets["device_type"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_device = st.selectbox(
        "Filter by device type",
        ["All"] + device_options,
    )

    filtered_assets = assets.copy()

    if selected_device != "All":
        filtered_assets = filtered_assets[
            filtered_assets["device_type"] == selected_device
        ]

    st.dataframe(
        filtered_assets,
        use_container_width=True,
        hide_index=True,
    )


# ==================================================
# TAB 2 — RISK ASSESSMENT
# ==================================================

with tab2:

    st.subheader("IoT Security Risk Assessment")

    col1, col2 = st.columns([3, 1])

    with col1:

        st.markdown("**Risk Severity Distribution**")

        # Preserve severity order:
        # Critical -> High -> Medium -> Low

        st.bar_chart(
            risk_chart_data,
            x="Risk Level",
            y="Asset Count",
            sort=False,
        )

    with col2:

        st.markdown("**Risk Assessment Summary**")

        for level in RISK_ORDER:
            st.metric(
                f"{level} Risk",
                int(risk_distribution[level]),
            )

    st.markdown("**Risk Register**")

    selected_risk = st.selectbox(
        "Filter by risk level",
        ["All"] + RISK_ORDER,
    )

    filtered_risks = risks.copy()

    if selected_risk != "All":
        filtered_risks = filtered_risks[
            filtered_risks["risk_level"]
            .astype(str)
            .str.strip()
            .str.title() == selected_risk
        ]

    filtered_risks = filtered_risks.sort_values(
        "risk_score",
        ascending=False
    )

    st.dataframe(
        filtered_risks,
        use_container_width=True,
        hide_index=True,
    )


# ==================================================
# TAB 3 — GRC ASSESSMENT
# ==================================================

with tab3:

    st.subheader("Governance, Risk and Compliance")

    st.markdown("**NIST CSF 2.0 Control Mapping**")

    st.dataframe(
        controls,
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("**GRC Assessment Findings**")

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Total Findings",
            len(grc)
        )

    with col2:
        st.metric(
            "Mapped Controls",
            controls["nist_csf_2_control"].nunique()
        )

    st.markdown("**Findings by NIST CSF Control**")

    control_counts = (
        grc["nist_csf_2_control"]
        .value_counts()
    )

    st.bar_chart(control_counts)

    st.markdown("**GRC Gap Register**")

    st.dataframe(
        grc,
        use_container_width=True,
        hide_index=True,
    )

    st.warning(
        "Assessment findings indicate potential "
        "security control gaps requiring review. "
        "They do not establish regulatory noncompliance."
    )


# ==================================================
# TAB 4 — ML ANOMALY DETECTION
# ==================================================

with tab4:

    st.subheader("Machine Learning Anomaly Detection")

    st.caption(
        "Isolation Forest analysis using synthetic "
        "healthcare IoT MQTT telemetry."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Total Observations",
            len(anomalies)
        )

    with col2:
        st.metric(
            "Normal Observations",
            normal_count
        )

    with col3:
        st.metric(
            "Detected Anomalies",
            detected_count if unknown_count == 0 else "Check labels"
        )

    if unknown_count:
        st.warning(
            f"{unknown_count} prediction labels could not "
            "be classified. Check the model output format."
        )

    st.markdown("**ML Prediction Distribution**")

    prediction_counts = (
        anomalies["detection_status"]
        .value_counts()
        .reindex(
            ["Normal", "Anomaly", "Unknown"],
            fill_value=0
        )
    )

    st.bar_chart(prediction_counts)

    st.markdown("**Anomaly Detection Results**")

    st.dataframe(
        anomalies,
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("**Anomaly Scores by Observation**")

    score_data = anomalies[
        ["anomaly_score"]
    ].copy()

    score_data.index = range(
        1,
        len(score_data) + 1
    )

    score_data.index.name = "Observation"

    st.line_chart(score_data)

    st.info(
        "Anomalous observations are statistical "
        "outliers, not confirmed cybersecurity incidents. "
        "Model evaluation is based on a small synthetic "
        "dataset and does not demonstrate real-world accuracy."
    )


# ==================================================
# 6. EXPORT SECURITY ANALYSIS
# ==================================================

st.divider()

st.subheader("Export Security Analysis")

export_options = {
    "Asset Inventory": assets,
    "Risk Register": risks,
    "GRC Gap Register": grc,
    "Anomaly Detection Results": anomalies,
    "NIST CSF Control Mapping": controls,
}

export_name = st.selectbox(
    "Select dataset to export",
    list(export_options.keys()),
)

st.download_button(
    label="Download CSV",
    data=export_options[export_name].to_csv(
        index=False
    ),
    file_name=(
        export_name.lower().replace(" ", "_") + ".csv"
    ),
    mime="text/csv",
)

st.caption(
    "Healthcare IoT Security + GRC + AI | "
    "Synthetic Cybersecurity Portfolio Project"
)
