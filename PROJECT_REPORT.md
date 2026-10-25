# CYBERSENTINEL AI — EMAIL THREAT DETECTION SYSTEM
## MINI PROJECT REPORT

**Submitted in partial fulfillment for the award of the degree of**

### BACHELOR OF TECHNOLOGY
**in**
### INFORMATION TECHNOLOGY

---

### Submitted by:
* **SHRI HARI S** — **(25IT165)**
* **SIDDHARTH T** — **(25IT167)**

---

### Under the Guidance of:
**Mr. M. ASHOK KUMAR**, Assistant Professor  
Department of Information Technology  
**KPR INSTITUTE OF ENGINEERING AND TECHNOLOGY**  
(Autonomous)  
Arasur, Coimbatore – 641 407, Tamil Nadu, India

**ANNA UNIVERSITY : CHENNAI 600 025**  
**OCTOBER 2026**

---

<div style="page-break-after: always;"></div>

## ANNA UNIVERSITY : CHENNAI 600 025

### BONAFIDE CERTIFICATE

Certified that this project report titled **"CYBERSENTINEL AI — EMAIL THREAT DETECTION SYSTEM"** is the bonafide work of:

* **SHRI HARI S** (**25IT165**)
* **SIDDHARTH T** (**25IT167**)

who carried out the mini project work under my supervision.

<br><br>

| **SIGNATURE** | **SIGNATURE** |
| :--- | :--- |
| **Mr. M. ASHOK KUMAR** | **Dr. I C AMITHA** |
| **SUPERVISOR**, | **HEAD OF THE DEPARTMENT**, |
| Assistant Professor, | Associate Professor, |
| Department of Information Technology, | Department of Information Technology, |
| KPR Institute of Engineering and Technology, | KPR Institute of Engineering and Technology, |
| Arasur, Coimbatore – 641 407. | Arasur, Coimbatore – 641 407. |

<br><br>

Submitted for the Project Viva-Voce examination held on: `________________________`

<br><br>

**INTERNAL EXAMINER** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; **EXTERNAL EXAMINER**

---

<div style="page-break-after: always;"></div>

## ABSTRACT

Email remains the predominant communication channel across academic, personal, and corporate environments. Consequently, email vectors account for over 85% of initial cyber intrusions, primarily through phishing, Business Email Compromise (BEC), credential harvesting, and deceptive hyperlink redirection. Traditional corporate security platforms often rely on complex, proprietary machine learning models that operate as "black boxes," leaving students, junior security analysts, and end-users without an understanding of *why* an email was flagged. Furthermore, novice users routinely fall victim to lookalike domains, deceptive subdomains, and obfuscated URLs due to a lack of immediate, explainable feedback.

This project presents **CyberSentinel AI**, a web-based, explainable Email Threat Detection and Forensic System developed using Python and Flask. The platform enables users to submit suspicious email content alongside sender addresses for real-time analysis. The core engine applies transparent, rule-based heuristic algorithms to evaluate sender domain spoofing, psychological urgency triggers, credential harvesting patterns, financial extortion, and malicious link indicators. In addition, an offline URL Forensic module decomposes hyperlinks to detect direct IP-address URLs, URL shorteners, brand typosquatting, and subdomain deception without initiating dangerous outbound network connections.

The system calculates an explainable, normalized Risk Score (0–100) and categorizes threats into Safe, Suspicious, or High Risk, accompanied by detailed rationale and defensive remediation steps. The front-end interface is implemented with HTML5, CSS3, and JavaScript, designed as a modern Security Operations Center (SOC) dashboard. The project serves both as a functional defensive utility and an educational tool for undergraduate IT students to understand email threat vectors and heuristic analysis fundamentals.

**Keywords:** Cybersecurity, Email Threat Detection, Phishing Detection, URL Forensics, Heuristic Analysis, Explainable AI, Flask, Python.

---

<div style="page-break-after: always;"></div>

## LIST OF ABBREVIATIONS

| Abbreviation | Full Form |
| :--- | :--- |
| **AI** | Artificial Intelligence |
| **API** | Application Programming Interface |
| **BEC** | Business Email Compromise |
| **CSS** | Cascading Style Sheets |
| **DNS** | Domain Name System |
| **HTML** | HyperText Markup Language |
| **HTTP** | HyperText Transfer Protocol |
| **HTTPS** | HyperText Transfer Protocol Secure |
| **IoC** | Indicator of Compromise |
| **IP** | Internet Protocol |
| **IPv4** | Internet Protocol Version 4 |
| **IT** | Information Technology |
| **JS** | JavaScript |
| **MFA** | Multi-Factor Authentication |
| **MitM** | Man-in-the-Middle |
| **REST** | Representational State Transfer |
| **RFC** | Request for Comments |
| **SLD** | Second-Level Domain |
| **SOC** | Security Operations Center |
| **TLD** | Top-Level Domain |
| **UI / UX** | User Interface / User Experience |
| **URL** | Uniform Resource Locator |
| **XSS** | Cross-Site Scripting |

---

<div style="page-break-after: always;"></div>

## TABLE OF CONTENTS

| Chapter | Title | Page No. |
| :---: | :--- | :---: |
| | **Bonafide Certificate** | **ii** |
| | **Abstract** | **iii** |
| | **List of Abbreviations** | **iv** |
| **1** | **Introduction** | **1** |
| | 1.1 Background | 1 |
| | 1.2 Overview of the Project | 1 |
| | 1.3 Need for the Project | 2 |
| | 1.4 Scope of the Project | 2 |
| | 1.5 Organization of the Report | 2 |
| **2** | **Problem Statement and Objectives** | **3** |
| | 2.1 Problem Statement | 3 |
| | 2.2 Objectives | 3 |
| **3** | **Existing System and Proposed System** | **4** |
| | 3.1 Existing System | 4 |
| | 3.2 Proposed System | 4 |
| | 3.3 Comparison of Existing and Proposed Systems | 5 |
| **4** | **System Requirements** | **6** |
| | 4.1 Functional Requirements | 6 |
| | 4.2 Non-Functional Requirements | 6 |
| | 4.3 Hardware and Software Requirements | 7 |
| **5** | **System Design** | **8** |
| | 5.1 Solution Design | 8 |
| | 5.2 System Architecture | 8 |
| | 5.3 System Workflow | 9 |
| | 5.4 Module Description | 10 |
| | 5.5 Key Heuristic Features | 11 |
| **6** | **Implementation** | **12** |
| | 6.1 Technology Stack | 12 |
| | 6.2 Implementation Details | 12 |
| | 6.3 Sender & Text Heuristic Engine | 13 |
| | 6.4 Safe Offline URL Forensic Engine | 13 |
| | 6.5 User Interface & SOC Telemetry | 14 |
| **7** | **Results and Output Screens** | **15** |
| **8** | **Testing** | **18** |
| | 8.1 Testing Approach | 18 |
| | 8.2 Test Cases and Verification | 18 |
| **9** | **Impact, Challenges and Future Enhancements** | **20** |
| | 9.1 Impact Analysis | 20 |
| | 9.2 Challenges Faced | 20 |
| | 9.3 Future Enhancements | 21 |
| **10** | **Conclusion** | **22** |
| | **References** | **23** |

---

<div style="page-break-after: always;"></div>

## CHAPTER 1
## INTRODUCTION

### 1.1 Background
Electronic mail remains the cornerstone of modern personal, scholastic, and business communication. With over 340 billion emails transmitted globally each day, email systems represent the single largest target surface for malicious cyber threat actors. Phishing, social engineering, spoofed enterprise notices, and Business Email Compromise (BEC) account for a substantial percentage of data breaches and financial losses worldwide.

Traditional cyber defenses in universities and small organizations rely either on standard spam filters or opaque cloud-based security tools. These mechanisms lack transparency, often failing to educate end-users on *how* an email was identified as malicious or what red flags were contained within its headers and content.

### 1.2 Overview of the Project
**CyberSentinel AI — Email Threat Detection System** is an educational, interactive web application developed with Python and Flask. It empowers users to paste suspicious email text, subject lines, and sender addresses into a centralized Security Operations Center (SOC) dashboard.

The application incorporates a transparent, rule-based heuristic analysis engine that executes multi-vector checks:
1. **Sender Address Inspection**: Scrutinizes top-level domain (TLD) reputations, typosquatted brand names, and consumer webmail impersonation.
2. **Behavioral & Social Engineering Patterns**: Extracts indicators of credential harvesting, urgent financial coercion, fear-inducing threats, and advance-fee scam lures.
3. **Safe Offline URL Forensic Analysis**: Extracts all embedded hyperlinks and performs static offline evaluation—flagging direct IP hosting, URL shorteners, subdomain brand deception, and character substitution without visiting untrusted web destinations.
4. **Explainable Risk Scoring**: Generates an aggregated, weighted score (0–100) and displays clear technical explanations for every flagged indicator.

### 1.3 Need for the Project
* **High Phishing Vulnerability**: Students and office staff frequently click malicious links due to deceptive visual formatting.
* **Lack of Explainability**: Mainstream email clients mark messages as "Spam" without detailing the underlying indicators, hindering user cybersecurity awareness.
* **Complex Enterprise Tools**: Full-scale enterprise email gateways (SEGs) require complex network routing and commercial licensing, making them inaccessible for classroom learning.
* **Safe Sandbox Requirement**: Students need a safe environment to examine malicious email samples without risking network malware execution.

### 1.4 Scope of the Project
The scope encompasses a standalone, locally hosted cybersecurity analysis platform. It provides a web interface with 1-click test datasets, heuristic scoring algorithms, offline URL parsing, and a RESTful API endpoint (`/api/analyze`). The system does not access private inbox credentials or transmit emails, ensuring privacy and safe execution on Windows 11 development environments.

### 1.5 Organization of the Report
* **Chapter 2** defines the problem statement and specific objectives.
* **Chapter 3** compares traditional approaches with the proposed CyberSentinel system.
* **Chapter 4** outlines functional, non-functional, hardware, and software requirements.
* **Chapter 5** presents system design, architectural schematics, and workflow diagrams.
* **Chapter 6** details the implementation across front-end and back-end modules.
* **Chapter 7** illustrates the user interface and experimental output results.
* **Chapter 8** details the black-box functional testing strategy and test cases.
* **Chapter 9** analyzes practical impact, engineering challenges, and future enhancements.
* **Chapter 10** summarizes the conclusions drawn from the project.

---

<div style="page-break-after: always;"></div>

## CHAPTER 2
## PROBLEM STATEMENT AND OBJECTIVES

### 2.1 Problem Statement
In educational and corporate environments, email users are constantly confronted with sophisticated social engineering attacks. Adversaries exploit human cognitive biases—such as fear of account termination, deadline pressure, or unexpected monetary incentives—to coax victims into disclosing credentials or clicking weaponized links. Existing spam detection mechanisms operate behind closed server architectures and offer no explainability to users. Moreover, novice computer users are unable to distinguish between legitimate corporate domains and lookalike domains (e.g., `paypa1-security.xyz` vs. `paypal.com`).

There is a critical need for an accessible, lightweight, and explainable email threat analysis system that dissects email telemetry, evaluates threats using transparent heuristic algorithms, inspects hyperlinks safely offline, and educates users through actionable forensic reporting.

### 2.2 Objectives
1. **Develop an Accessible Web Platform**: Build an intuitive, browser-accessible Flask application adhering to modern cybersecurity SOC aesthetics.
2. **Implement Multi-Vector Heuristic Detection**: Formulate rule-based regular expression filters to detect credential solicitation, financial urgency, and fear-based coercion.
3. **Analyze Sender Telemetry**: Identify domain anomalies, high-risk disposable TLD extensions, and free mail providers impersonating enterprise entities.
4. **Build a Safe Offline URL Forensic Engine**: Extract hyperlinks and evaluate indicators (raw IPv4 hosts, URL shorteners, subdomain brand spoofing, and typosquatting) without initiating dangerous network traffic.
5. **Formulate Explainable Scoring**: Calculate a normalized 0–100 risk score that avoids false convictions on single weak indicators while highlighting correlated threat patterns.
6. **Integrate Preloaded Test Datasets**: Provide instant 1-click sample emails covering phishing, CEO fraud, advance-fee scams, lookalike domains, and legitimate baselines.
7. **Generate Actionable Remediation Guidance**: Deliver step-by-step incident response advice based on the calculated severity level.

---

<div style="page-break-after: always;"></div>

## CHAPTER 3
## EXISTING SYSTEM AND PROPOSED SYSTEM

### 3.1 Existing System
The existing security ecosystem relies on commercial Secure Email Gateways (SEGs), client-side spam filters, or manual human inspection. In typical institutional setups:
* Emails are tagged as "Junk" or "Spam" based on centralized server reputation without end-user visibility.
* Users must manually copy links and risk opening them in browsers to verify their authenticity.
* Heuristics are opaque, leaving users unaware of deceptive brand manipulations like `micros0ft.com` or `login.microsoft.com.attacker.com`.
* No educational scoring breakdown is provided to teach students or staff how to spot similar attacks in the future.

### 3.2 Proposed System
The proposed **CyberSentinel AI** system transforms threat detection into an interactive, transparent forensic workflow:
* **Interactive Telemetry Input**: Users paste email headers and body text or choose pre-configured samples for immediate analysis.
* **Dual-Layer Heuristic Engine**: Simultaneously analyzes textual social engineering cues and deep hyperlink structures.
* **Safe Offline URL Deconstruction**: Decomposes URLs into scheme, hostname, path, and credentials locally, highlighting anomalies such as raw IP hosting and URL shorteners without making server requests.
* **Granular Explainability**: Every flagged phrase or deceptive link is paired with an educational explanation of the attacker's psychological or technical tactic.
* **Graduated Risk Meter**: Normalized scoring distinguishes between low-threat informational items, medium-suspicion indicators, and critical multi-indicator attacks.

### 3.3 Comparison of Existing and Proposed Systems

**Table 1: Comparison of Existing and Proposed Systems**

| Feature / Aspect | Existing System (Traditional Filters) | Proposed System (CyberSentinel AI) |
| :--- | :--- | :--- |
| **Detection Methodology** | Closed-source spam filters / static blacklists | Transparent, explainable rule-based heuristics |
| **URL Evaluation** | May require external DNS / online threat pings | 100% safe offline syntactic & domain deconstruction |
| **Explainability** | Opaque binary classification (Inbox vs. Spam) | Line-by-line justification for every detected indicator |
| **Domain Spoofing Check** | Basic SPF/DKIM validation | Detects subdomain brand spoofing & typosquatting |
| **Educational Value** | Low (no feedback to user) | High (tailored for IT students and SOC trainees) |
| **Deployment Complexity** | Requires MX record routing and mail server access | Lightweight local Flask server (zero external dependency) |
| **Multi-Indicator Logic** | Often penalizes single flags aggressively | Differentiates single cautions from correlated threats |
| **Interactive Testing** | Requires real email inbox transmission | Preloaded with safe, representative phishing presets |

---

<div style="page-break-after: always;"></div>

## CHAPTER 4
## SYSTEM REQUIREMENTS

### 4.1 Functional Requirements

#### User & Input Management Module
* The user shall be able to input sender email addresses and email body text into designated form fields.
* The system shall offer 1-click pre-fill buttons for representative threat categories (Phishing, BEC, Lottery Scam, Lookalike Domain, and Clean Corporate).
* The user shall be able to reset form fields with a single click.

#### Heuristic Threat Engine Module
* The system shall inspect sender addresses for format validity, high-risk TLDs (`.xyz`, `.top`, `.tk`, etc.), and free webmail impersonation.
* The system shall match body text against compiled regular expression collections covering:
  - Credential Harvesting (passwords, PINs, account verification).
  - Urgent Financial Demands (wire transfers, overdue invoices, cryptocurrency).
  - Psychological Fear & Urgency (account suspension, legal notices, 24-hour deadlines).
  - Advance-Fee Scam Lures (lottery jackpots, inheritance funds).

#### Safe Offline URL Forensic Module
* The system shall extract all hyperlinks matching HTTP, HTTPS, and domain structures.
* The system shall decompose URLs into hostname, scheme, path, and query without connecting to the remote host.
* The system shall evaluate:
  - Direct IPv4 addresses used as hostnames.
  - Known obfuscating URL shortener services.
  - Subdomain brand deception (e.g. `brand.com.attacker.com`).
  - Character substitution and homoglyphs (e.g. `paypa1`, `micros0ft`).
  - Unencrypted HTTP transmitting sensitive authentication actions.

#### Reporting & Scoring Module
* The system shall calculate an explainable Risk Score (0–100) and assign risk tiers: Safe (0–24), Suspicious (25–59), and Dangerous (60–100).
* The system shall render forensic result cards specifying the indicator, severity, exact trigger string, and remediation actions.

### 4.2 Non-Functional Requirements
* **Usability**: Responsive, dark-themed SOC layout accessible across standard desktop and mobile web browsers.
* **Safety & Privacy**: Absolute offline operation; no user data, email content, or URLs are communicated to external servers.
* **Performance**: Real-time heuristic evaluation delivering results in under 50 milliseconds on standard computing hardware.
* **Maintainability & Portability**: Standard Python code utilizing built-in modules (`re`, `urllib.parse`) and minimal third-party dependencies (`Flask==3.0.3`).

### 4.3 Hardware and Software Requirements

**Table 2: Hardware and Software Requirements**

| Item | Minimum Specification | Recommended Specification |
| :--- | :--- | :--- |
| **Processor** | Intel Core i3 / AMD Ryzen 3 (2.0 GHz) | Intel Core i5 / AMD Ryzen 5 or above |
| **System Memory (RAM)** | 4 GB | 8 GB or higher |
| **Hard Disk Storage** | 500 MB free storage | 1 GB SSD storage |
| **Operating System** | Windows 10 (64-bit) | Windows 11 (64-bit) / Linux / macOS |
| **Programming Language** | Python 3.8 | Python 3.10 / 3.11 / 3.12 |
| **Web Framework** | Flask 3.0.3 | Flask 3.0.3 |
| **Front-End Technologies** | HTML5, CSS3, JavaScript (ES6) | HTML5, CSS3, JavaScript (ES6) |
| **Development IDE** | Visual Studio Code / PyCharm | Visual Studio Code / Antigravity IDE |
| **Version Control** | Git 2.30+ | Git and GitHub |
| **Web Browser** | Google Chrome 90+, Microsoft Edge, Firefox | Latest version of Chrome / Edge |

---

<div style="page-break-after: always;"></div>

## CHAPTER 5
## SYSTEM DESIGN

### 5.1 Solution Design
CyberSentinel AI is architected as a lightweight, model-view-controller (MVC) web application. The core logic executes entirely within the server-side Python runtime, ensuring that untrusted user inputs are parsed, scrubbed, and evaluated safely without exposing the client browser to malicious script injection.

The solution design emphasizes **explainability over black-box decision making**. Rather than presenting an arbitrary probability score, the engine itemizes each heuristic rule triggered, detailing why attackers utilize the specific technique and how users should respond.

### 5.2 System Architecture
The platform is organized into three primary architectural tiers:
1. **Presentation Tier (Client Layer)**: Renders the responsive HTML5/CSS3 user interface, executes client-side sample loading, and presents color-coded forensic reports.
2. **Application Tier (Flask Server Layer)**: Manages HTTP routing, handles form submissions, orchestrates the analysis pipeline, and serializes responses.
3. **Forensic Engine Tier (Heuristic & Rule Layer)**: Contains specialized inspection sub-modules:
   - *Sender Reputation Analyzer*
   - *Linguistic Urgency & Phishing Pattern Matcher*
   - *Static Offline URL Forensic Analyzer*
   - *Additive Weighted Risk Synthesizer*

```
+-------------------------------------------------------------------------+
|                         PRESENTATION TIER (UI)                          |
|   +--------------------------+          +---------------------------+   |
|   |   Telemetry Input Form   |          |   SOC Forensic Dashboard  |   |
|   |  (Sender / Body Text)    |          |  (Score, Warnings, URLs)  |   |
|   +------------+-------------+          +-------------^-------------+   |
+----------------|--------------------------------------|-----------------+
                 | HTTP POST                            | Rendered Template
+----------------|--------------------------------------|-----------------+
|                v        APPLICATION TIER (FLASK)      |                 |
|   +---------------------------------------------------+-------------+   |
|   |              Flask Controller (Route: '/')                      |   |
|   |         - Sanitizes Form Data    - Coordinates Pipeline         |   |
|   +------------------------------------+----------------------------+   |
+----------------------------------------|--------------------------------+
                                         | Calls
+----------------------------------------v--------------------------------+
|                        FORENSIC ENGINE TIER                             |
|   +--------------------+  +---------------------+  +----------------+   |
|   |  Sender Inspector  |  |  Pattern Matcher    |  | URL Forensics  |   |
|   |  - TLD Analysis    |  |  - Credentials      |  | - IP Address   |   |
|   |  - Free-mail Spoof |  |  - Wire / BEC       |  | - Shortener    |   |
|   |  - Lookalikes      |  |  - Fear / Urgency   |  | - Subdomain    |   |
|   +---------+----------+  +----------+----------+  +--------+-------+   |
|             |                        |                      |           |
|             +------------------------+----------------------+           |
|                                      |                                  |
|                                      v                                  |
|                    +------------------------------------+               |
|                    |   Weighted Risk Scoring Engine     |               |
|                    |   (0-100 Score & Remediation)      |               |
|                    +------------------------------------+               |
+-------------------------------------------------------------------------+
```

### 5.3 System Workflow
The workflow comprises five sequential stages:
1. **Input Ingestion**: The user inputs an email address and raw text, or selects a preloaded sample.
2. **Text Normalization & Link Extraction**: The engine strips leading/trailing whitespace, cleans punctuation, and extracts embedded URLs using regular expressions.
3. **Parallel Inspection**:
   - The sender is evaluated for brand mismatch, disposable TLDs, and format anomalies.
   - Text is scanned against categorized threat regex dictionaries.
   - Each extracted URL is parsed into protocol, host, and path to identify deceptive indicators.
4. **Weighted Synthesis & Multi-Indicator Evaluation**:
   - Individual indicator weights are summed.
   - URLs with isolated indicators are marked with caution notes to prevent false alarms, while multi-indicator links are escalated to high risk.
   - The total score is capped at 100 and mapped to Safe, Suspicious, or High Risk tiers.
5. **Report Generation**: The system renders the metrics grid, score progress bar, detailed warning cards, URL inspection cards, and incident response checklist.

### 5.4 Module Description

#### Module 1: Telemetry Parser & Sanitizer
Cleans raw text inputs and extracts URLs. It utilizes boundary-aware regular expressions to separate punctuation (periods, commas, closing parentheses) from actual web addresses.

#### Module 2: Sender Anomaly Inspector (`inspect_sender`)
Splits the sender string into username and domain components. It maintains collections of high-risk TLDs (`.xyz`, `.top`, `.tk`, `.ml`, etc.) and enterprise brand names (`paypal`, `microsoft`, `apple`). It flags instances where free webmail addresses impersonate corporate identities or use hyphenated lookalikes.

#### Module 3: Linguistic Urgency & Pattern Engine (`THREAT_PATTERNS`)
Maintains categorized regular expression patterns representing psychological exploitation:
* `credential_harvesting`: Matches phrases demanding password verifications, PINs, or account unlock actions.
* `urgent_payment_demand`: Matches wire transfer requests, gift card demands, and overdue invoice threats.
* `psychological_urgency`: Detects artificial time constraints (e.g., "within 24 hours", "final notice").
* `fake_rewards`: Identifies lottery claims, unexpected jackpot notifications, and inheritance lures.

#### Module 4: Safe Offline URL Forensic Engine (`analyze_single_url`)
Performs syntactic inspection using Python’s `urllib.parse` without making external network calls:
* Identifies direct IPv4 hosts using octet regular expressions.
* Detects URL shortener hostnames that conceal true destinations.
* Checks for subdomain deception where a brand name appears before a foreign domain.
* Detects typosquatting homoglyphs (`micros0ft`, `paypa1`, `amaz0n`).
* Flags unencrypted HTTP endpoints on sensitive authentication paths (`/login`, `/verify`).

#### Module 5: Risk Synthesizer & Scoring Engine (`analyze_email`)
Aggregates weighted scores from sender checks, keyword matches, and URL forensics. It caps the result between 0 and 100, assigns severity badges (`safe`, `warning`, `danger`), and produces defensive guidance tailored to the threat level.

---

<div style="page-break-after: always;"></div>

## CHAPTER 6
## IMPLEMENTATION

### 6.1 Technology Stack

**Table 3: Technology Stack**

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend Structure** | HTML5 | Semantic structure of inputs, cards, and forensic tables |
| **Frontend Styling** | CSS3 (Vanilla) | Custom SOC dark theme, glassmorphic cards, responsive flex/grid |
| **Client Scripting** | JavaScript (ES6) | Client-side sample loading, active button state, smooth scrolling |
| **Backend Language** | Python 3.8+ | Core business logic, regex matching, and forensic heuristics |
| **Web Framework** | Flask 3.0.3 | Routing, HTTP request processing, and Jinja2 template rendering |
| **URL Parsing** | Python `urllib.parse` | RFC-compliant URL component deconstruction |
| **Pattern Matching** | Python `re` module | High-performance regular expression search and extraction |
| **Version Control** | Git & GitHub | Source code repository hosting and tracking |
| **Development Environment**| VS Code / Windows 11 | Code authoring, terminal execution, and debugging |

### 6.2 Implementation Details
The application follows a clean single-controller Flask design pattern in `app.py`. Routes are defined for the root path (`/`) to handle both GET (initial page render) and POST (form analysis) requests, as well as a JSON API route (`/api/analyze`).

Jinja2 templates dynamically render the analysis report. When an analysis result is present, the interface displays visual metrics, the risk progress bar, itemized warning cards, and URL forensic tables. When no input has been submitted, a clean placeholder state is rendered.

### 6.3 Sender & Text Heuristic Engine
The heuristic engine operates on compiled regular expression dictionaries with pre-assigned weights:
* **Critical Severity (+30 pts)**: Explicit password solicitation or enterprise brand impersonation on consumer email domains.
* **Critical Severity (+25 pts)**: Urgent wire transfer demands or invoice fraud pressure.
* **High Severity (+20 pts)**: Threats of account closure, legal action, or 24-hour ultimatums.
* **Medium Severity (+15 pts)**: Unsolicited lottery notifications or high-risk TLD extensions.

Matches are deduplicated and summarized, providing the exact triggering phrase for user review.

### 6.4 Safe Offline URL Forensic Engine
The URL forensic analyzer processes extracted links through a multi-indicator pipeline. To prevent false accusations on isolated indicators:
* **0 Indicators**: Marked as `Clean / Low Suspicion` (Green).
* **1 Indicator**: Marked as `Suspicious (Needs Caution)` (Amber). A contextual note clarifies that single indicators (such as a URL shortener or unusual TLD) warrant caution rather than panic.
* **2+ Indicators**: Marked as `High Risk (Correlated Phishing Indicators)` (Red). Correlated indicators (such as a raw IP combined with an unencrypted login path) indicate deceptive intent.

### 6.5 User Interface & SOC Telemetry
The user interface in `templates/index.html` and `static/style.css` incorporates modern cybersecurity dashboard aesthetics:
* **Color System**: Deep navy-black canvas (`#070b14`), elevated surface tiles (`#0f172a`), neon cyan accents (`#06b6d4`), cyber green (`#10b981`), amber warning (`#f59e0b`), and threat crimson (`#ef4444`).
* **Typography**: Professional sans-serif (`Inter`) for interface readability and monospace (`JetBrains Mono`) for email addresses, URL strings, and technical telemetry.
* **Interactive Samples**: 5 preloaded sample buttons enable instant demonstration across varied threat models.

---

<div style="page-break-after: always;"></div>

## CHAPTER 7
## RESULTS AND OUTPUT SCREENS

The working prototype was tested with varied email formats, ranging from authentic corporate communications to complex multi-vector phishing attacks.

### 7.1 Preloaded Test Scenarios

#### Scenario 1: Brand Spoofing & Credential Theft Phishing
* **Sender**: `security-alert@paypa1-support-portal.xyz`
* **Subject**: *FINAL WARNING: Immediate Action Required - PayPal Account Suspended*
* **Link**: `http://192.168.1.105/paypal-login/verify.php`
* **Result**:
  - **Risk Score**: 95 / 100 (Dangerous Phishing Probability)
  - **Flagged Indicators**: Lookalike brand domain (`paypa1`), high-risk TLD (`.xyz`), credential harvesting ("verify your password"), psychological urgency ("within 24 hours"), direct IPv4 hyperlink, and unencrypted HTTP on an authentication path.

#### Scenario 2: Business Email Compromise (BEC) / CEO Wire Fraud
* **Sender**: `ceo.executive.office@gmail.com`
* **Subject**: *Confidential: Immediate Wire Transfer Needed Today*
* **Links**: None
* **Result**:
  - **Risk Score**: 75 / 100 (Dangerous Phishing Probability)
  - **Flagged Indicators**: Free webmail impersonating executive leadership, urgent wire transfer demand, overdue invoice pressure, and legal action threats. Correctly notes that zero URLs are present.

#### Scenario 3: Advance-Fee Lottery Scam (Single URL Shortener)
* **Sender**: `claims-department@euromillions-promo.tk`
* **Subject**: *Congratulations! You have won $2,500,000 USD*
* **Link**: `http://bit.ly/claim-jackpot-reward-2026`
* **Result**:
  - **Risk Score**: 55 / 100 (Suspicious / Medium Threat)
  - **URL Verdict**: Marked as `Suspicious (1 Indicator - Exercise Caution)` highlighting that the shortener conceals destination, avoiding false claim of outright malware on a single indicator.

#### Scenario 4: Subdomain Brand Spoofing (Lookalike Deception)
* **Sender**: `admin@office365-security-alert.xyz`
* **Subject**: *Microsoft 365: Urgent Action Required - Password Expiration Notice*
* **Link**: `http://login.microsoft.com.account-verification-portal.xyz/auth/reset`
* **Result**:
  - **Risk Score**: 90 / 100 (Dangerous Phishing Probability)
  - **URL Verdict**: Marked as `High Risk (3 Correlated Indicators)`. Correctly reveals that while `login.microsoft.com` appears as a prefix, the actual destination host is `account-verification-portal.xyz`.

#### Scenario 5: Legitimate Corporate Meeting Update (Clean Baseline)
* **Sender**: `sarah.jenkins@acmecorp.com`
* **Subject**: *Team Sync: Q3 Cybersecurity Project Roadmap*
* **Link**: `https://sharepoint.acmecorp.com/teams/q3-roadmap`
* **Result**:
  - **Risk Score**: 0 / 100 (Safe / Low Threat)
  - **URL Verdict**: Clean. Valid HTTPS, official corporate domain, zero threat warnings triggered.

---

<div style="page-break-after: always;"></div>

## CHAPTER 8
## TESTING

### 8.1 Testing Approach
Functional (black-box) testing was performed to validate all inputs, heuristic triggers, URL parsing routines, scoring boundaries, and interface interactions. Each feature was tested with both normal and adversarial inputs, and actual outputs were verified against expected cybersecurity results.

### 8.2 Test Cases and Verification

**Table 4: Test Cases and Verification Results**

| Test Case ID | Test Description | Input Data / Condition | Expected Result | Status |
| :---: | :--- | :--- | :--- | :---: |
| **TC-01** | Empty Input Submission | Blank sender and blank body text | Prevent submission or display prompt to provide email data | **PASS** |
| **TC-02** | Legitimate Email Evaluation | Safe corporate sender and meeting text with internal link | Score = 0/100, Badge = Safe, 0 warnings flagged | **PASS** |
| **TC-03** | Free Mail Corporate Impersonation | `support-apple@gmail.com` claiming to be Apple Support | Critical warning flagged: Free mail impersonating enterprise brand | **PASS** |
| **TC-04** | High-Risk Disposable TLD | Sender domain ending in `.xyz` or `.tk` | High severity warning: High-risk disposable TLD extension | **PASS** |
| **TC-05** | Credential Harvesting Detection | Text contains "verify your password immediately" | Critical warning flagged for password/credential solicitation | **PASS** |
| **TC-06** | Financial Extortion / BEC | Text contains "wire transfer immediately" and "overdue invoice" | Critical warning flagged for high-pressure monetary demand | **PASS** |
| **TC-07** | Direct IP Address in URL | Hyperlink formatted as `http://192.168.1.1/login` | High severity URL flag: Direct IP address used as host | **PASS** |
| **TC-08** | URL Shortener Isolated Check | Link containing `http://bit.ly/sample-link` | Marked as Suspicious (1 Flag) with caution note; not labeled malicious | **PASS** |
| **TC-09** | Subdomain Lookalike Spoofing | `http://login.microsoft.com.attacker-site.com` | High-risk URL flag: Subdomain brand spoofing detected | **PASS** |
| **TC-10** | Preloaded Sample Loader Buttons | Clicking "PayPal Account Suspension" button | Form inputs pre-fill instantly and smooth-scroll to input area | **PASS** |
| **TC-11** | Form Reset Functionality | Clicking "Reset" button | Clears sender, clears textarea, removes active sample highlight | **PASS** |
| **TC-12** | REST API Endpoint | POST JSON payload to `/api/analyze` | Returns HTTP 200 with complete JSON risk metrics & URL breakdown | **PASS** |

---

<div style="page-break-after: always;"></div>

## CHAPTER 9
## IMPACT, CHALLENGES AND FUTURE ENHANCEMENTS

### 9.1 Impact Analysis
* **For Students and Trainees**: Demystifies email security by explaining the specific social engineering triggers and technical link deceptions used by attackers.
* **For Academic Institutions**: Provides an accessible, zero-cost, locally hostable cybersecurity laboratory tool for teaching practical email forensic analysis.
* **For End Users**: Demonstrates how to spot deceptive subdomain tricks and free-mail impersonation before clicking hazardous links.

### 9.2 Challenges Faced
1. **Punctuation Attachment in URL Extraction**: URLs placed at the end of sentences often captured periods or brackets (e.g. `http://site.com).`). This was resolved by implementing trailing punctuation trimming.
2. **Subdomain vs. Registered Domain Discrimination**: Accurately distinguishing between authentic multi-level domains (e.g. `teams.microsoft.com`) and spoofed subdomains (`microsoft.com.attacker.com`) without an external WHOIS database. Resolved by inspecting token positions relative to the TLD.
3. **Avoiding Single-Flag False Positives**: Preventing common URL shorteners from immediately branding an email as "Dangerous Malware." Resolved by implementing single-indicator caution labeling.

### 9.3 Future Enhancements
* **Machine Learning Classification**: Train a Naive Bayes or Logistic Regression model on public datasets (such as SpamAssassin or the Enron dataset) to augment rule-based heuristics.
* **RFC 822 Email Header Inspection**: Implement an `.eml` file upload parser to examine SPF, DKIM, and DMARC authentication headers.
* **Safe Screenshot Sandboxing**: Integrate a headless browser sandbox (e.g., Playwright) to render link previews in an isolated container.
* **Browser Extension Integration**: Package the heuristic engine into a lightweight Chrome/Edge extension for direct inbox warnings.

---

<div style="page-break-after: always;"></div>

## CHAPTER 10
## CONCLUSION

The **CyberSentinel AI — Email Threat Detection System** successfully delivers an explainable, responsive, and lightweight cybersecurity platform tailored for undergraduate IT education. By synthesizing rule-based pattern matching, sender reputation heuristics, and safe offline URL forensic analysis, the system accurately detects email threats while explaining *why* each indicator is suspicious.

The prototype demonstrates that effective security analysis does not require opaque, resource-intensive cloud services. Developing this project provided extensive hands-on experience in full-stack Python/Flask engineering, regular expression optimization, network protocol analysis, UI/UX design, and defensive cybersecurity methodology.

**INSPECT TELEMETRY | ANALYZE HEURISTICS | PREVENT PHISHING**

---

<div style="page-break-after: always;"></div>

## REFERENCES

1. **Stallings, W.** (2018). *Cryptography and Network Security: Principles and Practice* (7th ed.). Pearson Education.
2. **Hadnagy, C.** (2018). *Social Engineering: The Science of Human Hacking* (2nd ed.). John Wiley & Sons.
3. **Grinberg, M.** (2018). *Flask Web Development: Developing Web Applications with Python* (2nd ed.). O'Reilly Media.
4. **Berners-Lee, T., Fielding, R., & Masinter, L.** (2005). *Uniform Resource Identifier (URI): Generic Syntax*. RFC 3986, Internet Engineering Task Force (IETF).
5. **Cranor, L. F., & Garfinkel, S.** (2005). *Security and Usability: Designing Secure Systems That People Can Use*. O'Reilly Media.
6. **APWG (Anti-Phishing Working Group)**. (2025). *Phishing Activity Trends Report*. APWG Reports.
7. **Python Software Foundation**. (2026). *Python Documentation: `urllib.parse` and `re` Modules*. Retrieved from https://docs.python.org/3/
8. **Pallets Projects**. (2024). *Flask Documentation (Version 3.0.x)*. Retrieved from https://flask.palletsprojects.com/
