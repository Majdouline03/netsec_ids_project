# NetSec IDS Project  
Offline Intrusion Detection System for Network Traffic Analysis

## Project Overview

This project implements an **offline Intrusion Detection System (IDS)** developed in Python for the analysis of network traffic captured in **PCAP files**.  
The system analyzes recorded traffic to identify **suspicious or malicious behaviors** using rule-based detection techniques and presents the results through a graphical user interface.

The project is developed as part of a **Network Security** course and focuses on applying theoretical concepts such as network attacks, traffic analysis, and intrusion detection to a practical use case.

---

## Objectives

The main objectives of this project are:

- Analyze network traffic stored in PCAP files  
- Detect suspicious behaviors and common network attacks  
- Classify detected events based on severity  
- Present results in a clear and interpretable way  
- Evaluate detection results using benchmark datasets  

The IDS operates **offline** and does not monitor live network traffic.

---

## Dataset

The project is based on the **CIC-IDS2017** benchmark dataset, which includes:

- Realistic network traffic captures
- Multiple attack scenarios (e.g., Port Scan, DoS, DDoS, Brute Force)
- Raw PCAP files
- Labeled flow-level data used for evaluation

Raw PCAP files are used for traffic analysis, while labeled CSV files are used only for **benchmarking and evaluation**.

> Note: Dataset files are not included in this repository.

---

## System Overview

The system follows a sequential analysis pipeline:

1. PCAP file is provided as input  
2. Network packets are parsed and relevant features are extracted  
3. Traffic is aggregated over time windows  
4. Rule-based detection algorithms identify suspicious behaviors  
5. Severity levels are assigned to detected events  
6. Results are saved and visualized through a dashboard  

---

## Detection Rules Implemented

The IDS detects the following types of suspicious behaviors:

1. **Port Scanning Detection**  
2. **Packet Flooding (DoS/DDoS-like Behavior)**  
3. **Anomalous Packet Rate per IP**  
4. **SYN Flood Detection**  
5. **Repeated Failed Connection Attempts**  
6. **Abnormal Protocol Usage**

Each detection rule produces alerts with an explanation and a severity level (Low, Medium, High).


## Project Structure

netsec-ids/
├── data/
│ ├── raw_pcaps/ # PCAP files (not tracked)
│ └── labels/ # Dataset labels for evaluation
│
├── results/
│ ├── alerts/ # IDS alerts output
│ ├── reports/ # Summary reports
│ └── logs/ # Execution logs
│
├── src/
│ ├── engine/ # IDS core (parsing, detection, severity)
│ ├── ui/ # Streamlit dashboard
│ └── evaluation/ # Benchmarking and metrics
│
├── requirements.txt
├── README.md
└── .gitignore


---

## Technologies Used

- **Python 3**
- **PyShark / Scapy** for PCAP parsing
- **Pandas & NumPy** for data processing
- **Streamlit** for graphical user interface
- **Matplotlib / Plotly** for visualization
- **Git & GitHub** for version control

---

## Collaboration and Version Control

The project is developed collaboratively using Git with a clear division of responsibilities:

- `engine` branch: IDS core logic and detection rules  
- `ui-eval` branch: User interface and evaluation modules  
- `main` branch: Stable, integrated version  

This structure ensures modular development and avoids conflicts.

---

## Limitations

- The IDS operates only on offline traffic  
- Detection is rule-based and does not use machine learning  
- Encrypted payloads are not inspected  
- Some application-layer attacks are outside the scope of detection  

These limitations are consistent with the educational scope of the project.

