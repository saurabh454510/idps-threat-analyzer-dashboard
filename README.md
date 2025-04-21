# 🛡️ IDPS Threat Analyzer

**Intrusion Detection and Prevention System (IDPS) Dashboard** with CSV upload, advanced attack classification, and visual threat analytics powered by a deep learning model.

---

## 🚀 Features

- 📁 Upload network traffic datasets (CSV format with 78 required features)
- 🧠 Predict threats using a pre-trained deep learning model (`idps_full_model.h5`)
- 🔍 Classify attacks into specific types (SYN Flood, DDoS, Port Scanning, etc.)
- 📊 Visualize threat probabilities, attack types, and data summaries
- 🧭 Dynamic gauge chart indicating average threat level
- 🖥️ Built with Dash, Plotly, and TensorFlow

---

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/your-username/idps-threat-analyzer.git
cd idps-threat-analyzer
2. Install dependencies
Create a virtual environment (optional) and install packages:

pip install -r requirements.txt
3. Add your trained model
Place your trained model file in the root directory:

idps_full_model.h5
Ensure your model matches the feature input shape defined in the script.
🚦 How to Run

python3 app.py
Then open your browser at:

http://localhost:8050
📂 CSV Format

Your input file must be a .csv containing all 78 required features such as:

destination_port
flow_duration
total_fwd_packets
packet_length_mean
ack_flag_count
flow_iat_std
(and many more…)
The complete list of features is defined in the FEATURES variable in app.py.
🧠 Attack Classifications

The app includes rules to detect and label known threats:

🔺 SYN Flood
🔺 DDoS Attack
🔺 Port Scanning
🔺 Brute Force Attempt
🔺 HTTP Flood
🔺 Slowloris Attack
🟡 Suspicious Activity
🟣 Data Exfiltration
🔍 Network Probing
✅ Normal Traffic
📊 Dashboard Overview

Upload Panel – Upload your .csv files
Threat Gauge – Real-time average threat visualization
Summary Tab – High-level stats & charts
Detailed Tab – Row-level predictions and threat labels
🧪 Sample Use Cases

Corporate network anomaly detection
Research on attack traffic patterns
Pre-processing stage for live IDS/IPS systems
📌 TODO / Future Features

🔄 Real-time packet stream support
🔐 Role-based authentication
📤 Export result reports (PDF/CSV)
📈 Extended model with sequence/time-based features


👨‍💻 Author
   Saurabh Kumar
   GitHub: saurabh454510



