# 🛡️ CyberSentinel AI — Email Threat Detection System

A beginner-friendly, transparent, rule-based email threat and phishing detection web application built with **Python** and **Flask**. Designed specifically for 2nd-year Information Technology (IT) and Computer Science students to understand heuristic email analysis, social engineering patterns, and defensive cybersecurity concepts.

---

## 📌 Project Overview

Phishing attacks and Business Email Compromise (BEC) remain the leading initial vectors for cyber attacks. While enterprise tools often rely on complex machine learning models, understanding **transparent rule-based heuristics** is the foundational first step for any cybersecurity student.

**CyberSentinel AI** inspects email telemetry (sender address, message headers, and body content) against a structured threat rule engine. It calculates a normalized **Risk Score (0–100)** and breaks down every flagged indicator with a technical explanation of *why* the tactic is dangerous.

> [!NOTE]
> **Safety Guarantee**: This application operates purely in a local sandbox mode. It **never** connects to live mail servers, accesses your personal email accounts, or sends actual emails.

---

## 🚀 Key Features

1. **Intuitive Flask Web Interface**: Clean, responsive Security Operations Center (SOC) dark theme with instant visual telemetry.
2. **Transparent Rule-Based Heuristics**:
   - **Sender Anomaly & Spoofing**: Detects lookalike domains (e.g. `paypa1`), high-risk disposable TLDs (`.xyz`, `.top`, `.tk`), and free webmail impersonation (`@gmail.com` claiming to be corporate bank support).
   - **Credential Harvesting**: Flags requests demanding passwords, PINs, or urgent account login verifications.
   - **Urgent Financial Demands / BEC**: Identifies unauthorized wire transfers, overdue invoice pressure, and gift card / cryptocurrency requests.
   - **Psychological Urgency & Fear**: Detects coercion keywords (e.g., *"account will be suspended within 24 hours"*, *"final warning"*, *"legal action"*).
   - **Safe Offline URL Forensics**: Deconstructs extracted links without connecting to them. Flags raw IPv4 addresses, URL shorteners, subdomain brand spoofing (`login.microsoft.com.attacker.com`), typosquatting homoglyphs, and embedded authentication redirects.
3. **Explainable Risk Scoring (0–100)**:
   - **0 – 24 (Safe / Low Threat)**: Green indicator, standard hygiene advice.
   - **25 – 59 (Suspicious / Medium Threat)**: Amber indicator, secondary verification recommended. Avoids claiming malice on single isolated flags (e.g., a URL shortener alone warrants caution, not instant panic).
   - **60 – 100 (Dangerous Phishing Attack)**: Red indicator, correlated multi-vector flags, and immediate incident response checklist.
4. **1-Click Preloaded Test Samples**:
   - 🚨 *PayPal Account Suspension* (Credential harvesting & fake IP link)
   - 💼 *Urgent Wire Transfer / CEO Fraud* (Business Email Compromise without links)
   - 🎁 *International Lottery Reward* (Advance-fee scam with URL shortener)
   - 🎣 *Microsoft 365 Account Update* (Subdomain lookalike spoofing & password lure)
   - ✅ *Legitimate Corporate Project Sync* (Clean corporate email baseline)
5. **REST API Endpoint**: Includes `/api/analyze` for students wanting to experiment with programmatic JSON testing or Python scripts.

---

## 📂 Project Structure

```text
CYBERSENTINEL_AI/
│
├── app.py                 # Core Flask backend & rule-based threat & URL engine
├── requirements.txt       # Minimal project dependencies (Flask)
├── .gitignore             # Excludes virtualenvs, cache, and OS files
├── README.md              # Project documentation & Windows 11 setup guide
│
├── templates/
│   └── index.html         # HTML5 frontend template with Jinja2 rendering
│
└── static/
    └── style.css          # Modern cybersecurity SOC dark theme stylesheet
```

---

## 💻 Windows 11 Installation & Setup Guide

Follow these step-by-step instructions in Windows PowerShell or Command Prompt.

### Prerequisites
- Windows 10 or 11
- Python 3.8 or higher installed on your system.
  *(Make sure **"Add Python to PATH"** was checked during installation!)*

To verify Python is installed, open PowerShell and run:
```powershell
python --version
```

---

### Step 1: Open PowerShell in the Project Directory
1. Open File Explorer and navigate to the project folder:
   `C:\Users\hari\Documents\CYBERSENTINEL_AI`
2. Right-click inside the folder and select **"Open in Terminal"** (or press `Win + R`, type `powershell`, and run:
   ```powershell
   cd C:\Users\hari\Documents\CYBERSENTINEL_AI
   ```

---

### Step 2: Create a Python Virtual Environment (Recommended)
A virtual environment keeps project dependencies isolated and prevents version conflicts.

```powershell
python -m venv venv
```

---

### Step 3: Activate the Virtual Environment

**In Windows PowerShell:**
```powershell
.\venv\Scripts\Activate.ps1
```

> [!TIP]
> **PowerShell Execution Policy Tip**:
> If Windows blocks the script with an error like `running scripts is disabled on this system`, run this command in PowerShell to allow it for your current session:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
> .\venv\Scripts\Activate.ps1
> ```

**In Windows Command Prompt (CMD):**
```cmd
venv\Scripts\activate.bat
```

When activated, you will see `(venv)` at the beginning of your terminal prompt.

---

### Step 4: Install Dependencies

Install Flask using the provided `requirements.txt`:
```powershell
pip install -r requirements.txt
```

---

### Step 5: Start the CyberSentinel Web Application

Run the application:
```powershell
python app.py
```

You will see output similar to:
```text
==================================================================
🛡️  CyberSentinel AI — Email Threat Detection System
🚀  Starting local Flask development server at: http://127.0.0.1:5000
💡  Press CTRL+C to stop the server
==================================================================
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

---

### Step 6: Access the Web Interface
Open your preferred web browser (Edge, Chrome, Firefox) and navigate to:
```text
http://127.0.0.1:5000
```

1. Click any of the **Quick Test Samples** at the top to load pre-configured emails.
2. Click **"Analyze Email Threat"**.
3. Review the **Risk Score**, **Verdict**, **Technical Indicators**, and **Educational Explanations**!

To stop the server at any time, switch to your PowerShell window and press `Ctrl + C`.

---

## 🧠 How the Rule-Based Detection Engine Works

```
                   +---------------------------+
                   |  Incoming Email Telemetry |
                   |  (Sender + Body Content)  |
                   +-------------+-------------+
                                 |
        +------------------------+------------------------+
        |                        |                        |
        v                        v                        v
+----------------+      +----------------+      +------------------+
| Sender Domain  |      | Link & URL     |      | Social Eng.      |
| Verification   |      | Extraction     |      | Regex Patterns   |
| (TLD / Spoof)  |      | (IP / Short)   |      | (Urgency / BEC)  |
+-------+--------+      +-------+--------+      +--------+---------+
        |                       |                        |
        +-----------------------+------------------------+
                                |
                                v
               +---------------------------------+
               |  Risk Score Calculation (0-100) |
               |  Weights & Explanations         |
               +----------------+----------------+
                                |
            +-------------------+-------------------+
            v                                       v
    [ Score >= 60 ]                         [ Score < 25 ]
   🔴 High Threat / Phishing               🟢 Safe / Clean Email
```

1. **Sender Heuristics (`inspect_sender`)**:
   - Compares the sender domain against high-risk top-level domains (`.xyz`, `.top`, `.tk`, etc.).
   - Detects brand name typosquatting and free webmail services impersonating corporate institutions.
2. **Link Heuristics (`inspect_links`)**:
   - Uses regular expressions to extract all URLs in the email text.
   - Flags raw IP addresses (e.g. `192.168.1.1`) commonly used to bypass domain blacklist filters.
   - Detects URL shorteners (`bit.ly`, `tinyurl.com`) that conceal malicious destinations.
3. **Keyword & Behavioral Patterns (`THREAT_PATTERNS`)**:
   - Scans for urgency triggers (fear of account termination, 24-hour ultimatums).
   - Identifies credential harvesting (passwords, PINs, secret tokens).
   - Flags financial demands (wire transfers, overdue invoices, gift cards).
4. **Additive Weighted Scoring (`analyze_email`)**:
   - Findings accumulate risk points (Critical: 25–30 pts, High: 15–20 pts, Medium: 10–15 pts).
   - The total score is capped at 100 for an intuitive percentage-based risk rating.

---

## 🔮 Future Enhancements (Ideas for Student Projects)

- [ ] **Natural Language Processing (NLP)**: Incorporate Python libraries like `nltk` or `spacy` for sentiment analysis and semantic urgency detection.
- [ ] **Machine Learning Classifier**: Train a `scikit-learn` Naive Bayes or Logistic Regression model on public datasets like the *Enron Spam Dataset* or *SpamAssassin*.
- [ ] **Email Header Parsing**: Add an `.eml` file uploader using Python's built-in `email` module to inspect SPF, DKIM, and DMARC authentication headers.
- [ ] **Threat Intelligence Integration**: Connect to free APIs like VirusTotal or PhishTank for real-time link reputation lookups.

---

## 📄 License
This project is created for educational purposes. Feel free to modify and expand it for academic coursework and capstone projects!
