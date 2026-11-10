# Healthcare IoT Security, GRC & AI

**This is an end-to-end, synthetic healthcare IoT cybersecurity portfolio project** to simulate real-world healthcare environment with combining asset inventory, risk prioritisation, governance and control mapping, MQTT telemetry simulation, machine-learning anomaly detection and a locally hosted AI security assistant.

The main purpose of this project is to apply the knowledge and skills gained through my recent cybersecurity studies to a practical healthcare environment. I wanted to simulate how the main building blocks of a healthcare IoT network work together and explore how security controls, risk management, monitoring and AI-assisted analysis can support a secure and compliant environment.

The project is designed to be further developed and expanded based on evolving business requirements, with a focus on supporting business growth while maintaining security, operational resilience and effective governance.

> **Educational laboratory only.** All device records, telemetry, risk assessments and findings are synthetic. The results are not evidence of a real-world incident, medical-device safety issue, regulatory noncompliance or control failure. AI recommendations require human review.

## Project at a glance

| Measure | Laboratory result |
| --- | ---: |
| Synthetic IoT assets | 20 |
| Risk register entries | 20 |
| High / Medium / Low risk entries | 5 / 12 / 3 |
| Potential GRC findings | 24 |
| Simulated telemetry observations evaluated | 10 |
| ML-flagged observations | 2 |
| Streamlit dashboard tabs | 5 |

These counts describe this specific synthetic dataset and are not generalised model-performance or compliance claims.

## Objectives

- Build an inventory of healthcare IoT devices and identify their security-relevant attributes.
- Assess and prioritise potential risks in a repeatable register.
- Map potential gaps to **NIST Cybersecurity Framework (CSF) 2.0** controls.
- Simulate IoT messaging and inspect telemetry using MQTT and Wireshark.
- Explore anomaly detection with Python and Isolation Forest.
- Present results in a Streamlit dashboard and generate evidence-first AI-assisted analysis using a **local Ollama** model.

## Architecture and workflow

```text
Synthetic healthcare IoT asset inventory
                |
                v
      Risk assessment register
                |
                v
      GRC mapping / gap register --------> NIST CSF 2.0 mapping
                |
                +-----------------------------+
                                              |
Synthetic MQTT traffic --> telemetry logs --> ML anomaly detection
                                              |
                                              v
                                CSV results and verified counts
                                              |
                                              v
                                 Streamlit dashboard (5 tabs)
                                              |
                         User selects an AI analysis and clicks Generate
                                              |
                                              v
                          Python-verified observations + local Ollama
                                              |
                                              v
                         Structured JSON validation / safe fallback
                                              |
                                              v
                         Human-review-labelled Markdown security report
```

The AI assistant does **not** independently verify facts. It provides key insights which need human validation. Python calculates the observations; Ollama generates a qualitative advisory which is screened before display.

## Milestones

| Milestone | Implementation | Outcome |
| --- | --- | --- |
| **1 - Asset inventory** | `src/generate_assets.py` | Generated 20 synthetic healthcare IoT asset records |
| **2 - Risk assessment** | `src/risk_assessment.py` | Risk scoring, classifications and prioritised register |
| **3 - GRC assessment** | `src/grc_assessment.py` | Potential findings mapped to NIST CSF 2.0 controls |
| **4 - IoT simulation** | `src/iot_traffic_simulator.py` | MQTT traffic simulation with Mosquitto and Wireshark inspection |
| **5 - ML anomaly detection** | `src/anomaly_detection.py` | Isolation Forest evaluation of synthetic telemetry |
| **6A - Dashboard** | `src/dashboard.py` | Streamlit visualisation of inventory, risks, GRC and ML results |
| **6B - AI assistant** | `src/ai_security_assistant.py` | Local Ollama analysis with structured JSON guardrails, integrated as the fifth dashboard tab |

## Technical stack

| Area | Technologies |
| --- | --- |
| Programming and data processing | Python, pandas |
| Machine learning | scikit-learn, Isolation Forest |
| IoT telemetry and inspection | MQTT, Mosquitto, paho-mqtt, Wireshark |
| Governance and security analysis | NIST CSF 2.0, risk and potential gap registers |
| Dashboard | Streamlit |
| Local AI | Ollama, `qwen2.5:1.5b` |
| Development environment | Ubuntu 22.04 VM, Windows host, Git and GitHub |

## Dashboard

Run `src/dashboard.py` to open five tabs:

1. **Asset Inventory:** device-type and firmware-status charts, filterable inventory.
2. **Risk Assessment:** ordered risk-severity chart and risk register.
3. **GRC Assessment:** control mapping, potential findings and NIST CSF distribution.
4. **ML Anomaly Detection:** predicted-label distribution, recorded anomaly scores and observation table.
5. **AI Security Assistant:** on-demand Security Posture Report, Anomaly Investigation or GRC Assessment, with Markdown export.

The dashboard also supports CSV export of the underlying project datasets.

## Selected findings from the synthetic dataset

### Risk register

The Python-calculated risk register contains **5 High**, **12 Medium** and **3 Low** entries. The five High-risk entries are:

| Asset ID | Device type | Recorded risk score |
| --- | --- | ---: |
| IOT-015 | Environmental Sensor | 8 |
| IOT-016 | Medication Dispenser | 8 |
| IOT-018 | Infusion Pump | 8 |
| IOT-008 | Medication Dispenser | 7 |
| IOT-020 | ECG Monitor | 7 |

### GRC mapping

The synthetic GRC register contains **24 potential findings across 20 assets**. These are counts of *findings*, not unique devices or proven compliance failures.

| NIST CSF 2.0 control | Potential findings |
| --- | ---: |
| DE.CM-01 | 9 |
| ID.AM-08 | 7 |
| ID.RA-05 | 5 |
| PR.IR-01 | 3 |
| **Total** | **24** |

### ML anomaly detection

The example evaluation contains **10 synthetic observations**, of which **2 were flagged** by the model. Both flagged records are associated with synthetic asset `IOT-002`. A flagged observation is a statistical outlier, **not** a confirmed cybersecurity incident, device malfunction or clinical event. This small synthetic evaluation does not establish production accuracy.

## AI Security Assistant: design and guardrails

The assistant runs locally with **Ollama** and the **Qwen2.5 1.5B** model. Its three analysis modes are:

- **Security Posture Report:** summarises verified risk counts and proposes investigation priorities.
- **Anomaly Investigation:** presents flagged observations and suggests data-quality and log-correlation checks.
- **GRC Assessment:** summarises potential control findings and suggests evidence-based follow-up.

**Evidence-first reporting workflow:**

1. Python reads the local CSV datasets and calculates the verified counts and recorded observations.
2. Ollama is asked for a short, structured JSON advisory containing implications, recommendations and limitations.
3. Python screens the generated fields for expected structure and selected unsupported content, including unwanted numerical claims and Chinese-character output.
4. If screening fails, the application uses a predefined safe fallback rather than displaying the rejected advisory.
5. The final Markdown report separates **Python-verified observations** from **AI-generated advice**, with explicit limitations and human-review notices.

**Guardrail limitations:** Passing automated screening does not guarantee factual accuracy, English-only text in every possible case, or freedom from misleading recommendations. The model does not determine actual compliance status, clinical significance, exploitability or incident severity. Outputs should be reviewed by a qualified human before any operational decision.

## Repository layout

```text
healthcare-iot-security-grc-ai/
├── data/                         # Synthetic inventory, risk, GRC and ML CSV files
├── evidence/                     # Project screenshots E01–E19
├── grc/                          # Control mapping
├── src/
│   ├── generate_assets.py
│   ├── risk_assessment.py
│   ├── grc_assessment.py
│   ├── iot_traffic_simulator.py
│   ├── anomaly_detection.py
│   ├── ai_security_assistant.py
│   └── dashboard.py
├── .gitignore
├── LICENSE
└── README.md
```

## Run locally

**Prerequisites:** Python 3, a working Python virtual environment, the project CSV datasets and a running local Ollama service with the `qwen2.5:1.5b` model. Install the Python dependencies used by the scripts (including `pandas`, `streamlit`, `requests`, `scikit-learn` and `paho-mqtt` where required). The MQTT simulation additionally uses a local MQTT broker such as Mosquitto.

From the repository root on Ubuntu:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pandas streamlit requests scikit-learn paho-mqtt
```

Install and configure Ollama separately, then confirm the model is available:

```bash
ollama pull qwen2.5:1.5b
ollama list
```

Start the dashboard:

```bash
python -m streamlit run src/dashboard.py
```

Open **http://localhost:8501** in the same VM or a browser with access to the Streamlit server. Select **AI Security Assistant**, choose an analysis type and click **Generate AI Report**. Ollama must be running and reachable at the endpoint configured in `src/ai_security_assistant.py` (the lab used `http://127.0.0.1:11434/api/generate`).

You can also run the assistant directly:

```bash
python src/ai_security_assistant.py
```

**Note:** The example commands install core packages, not a locked or fully tested dependency set. Python and package versions may need adjustment for your environment; inspect imports in the source files if a dependency is missing.

## Evidence gallery

The project includes milestone screenshots under [`evidence/`](evidence/). The final AI-assistant evidence is shown below.

### E17 — Security Posture Report

![AI Security Assistant — Security Posture Report](evidence/E17_AI_Security_Posture.png)

### E18 — Anomaly Investigation

![AI Security Assistant — Anomaly Investigation](evidence/E18_AI_Anomaly_Investigation.png)

### E19 — GRC Assessment

![AI Security Assistant — GRC Assessment](evidence/E19_AI_GRC_Assessment.png)

Earlier evidence **E01–E16** documents the inventory, risk, GRC, telemetry, ML and dashboard milestones. See the [`evidence/` folder](evidence/) for the available screenshots.

## Scope, ethics and limitations

- **Synthetic data only:** No real patient data, production credentials or organisational security records are required or intended.
- **No clinical interpretation:** Telemetry anomalies must not be interpreted as medical diagnoses or device safety events.
- **No compliance certification:** Mapped potential findings are hypotheses for review, not proof of regulatory noncompliance.
- **No production security claim:** The lab demonstrates a workflow, not a validated enterprise detection system.
- **Human oversight:** AI-generated recommendations are advisory and require evidence-based verification and approval.

## Skills demonstrated

Cybersecurity risk assessment · Asset management · NIST CSF 2.0 mapping · Security monitoring concepts · MQTT traffic analysis · Python automation · ML anomaly detection · Streamlit visualisation · Local LLM integration · Structured-output validation · Responsible AI reporting · Git/GitHub documentation

---

*Portfolio project for educational and professional development purposes.*
