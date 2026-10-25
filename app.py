"""
CyberSentinel AI — Email Threat Detection System
-------------------------------------------------
A beginner-friendly, rule-based cybersecurity web application built with Flask.
Designed for 2nd-year IT students to understand email threat vectors,
heuristic analysis, and phishing detection fundamentals.

Author: CyberSentinel Team
"""

import os
import re
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, send_file

app = Flask(__name__)

# -------------------------------------------------------------------------
# CYBER THREAT DETECTION RULE ENGINE (HEURISTIC & RULE-BASED)
# -------------------------------------------------------------------------

# 1. Suspicious Top-Level Domains (frequently abused in spam/phishing campaigns)
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.work', '.date', '.loan', '.racing', '.download', '.accountant', '.live'
}

# 2. Known URL shorteners that conceal the true destination URL
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly', 't.co',
    'cutt.ly', 'rebrand.ly', 'rb.gy', 'shorturl.at'
}

# 3. Impersonation / Typosquatting targets (lookalike domains often used to fool victims)
HIGH_VALUE_TARGETS = [
    'paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix',
    'bankofamerica', 'wellsfargo', 'chase', 'dropbox', 'facebook'
]

# 4. Pattern collections categorized by threat behavior
THREAT_PATTERNS = {
    'credential_harvesting': {
        'category': 'Credential Harvesting',
        'severity': 'Critical',
        'weight': 30,
        'description': (
            'The email solicits sensitive security credentials (passwords, PINs, or tokens). '
            'Legitimate institutions never request account passwords via email.'
        ),
        'patterns': [
            r'\b(?:verify|confirm|reset|update)\s+your\s+(?:password|credentials|login|passcode|pin)\b',
            r'\b(?:enter|type)\s+your\s+(?:password|current\s+password|security\s+code)\b',
            r'\baccount\s+suspended\s+unless\s+you\s+verify\b',
            r'\bclick\s+here\s+to\s+(?:unlock|reactivate|verify)\s+your\s+account\b',
            r'\bconfirm\s+your\s+identity\s+immediately\b',
            r'\blogin\s+credentials\s+have\s+expired\b'
        ]
    },
    'urgent_payment_demand': {
        'category': 'Urgent Financial Demand / BEC',
        'severity': 'Critical',
        'weight': 25,
        'description': (
            'High-pressure monetary requests often signal Business Email Compromise (BEC) '
            'or invoice fraud designed to bypass normal accounting verification.'
        ),
        'patterns': [
            r'\b(?:wire\s+transfer|transfer\s+funds?|send\s+money)\s+(?:immediately|urgently|today|now)\b',
            r'\bpay\s+within\s+(?:\d{1,2}\s+hours?|24\s*h|48\s*h)\b',
            r'\boverdue\s+invoice\b',
            r'\boutstanding\s+(?:balance|payment|bill)\s+must\s+be\s+cleared\b',
            r'\bgift\s+cards?\s+(?:purchase|buy|codes?)\b',
            r'\bcrypto(?:currency)?\s+payment\b',
            r'\bbitcoin\s+wallet\b'
        ]
    },
    'psychological_urgency': {
        'category': 'Urgency & Fear Tactics',
        'severity': 'High',
        'weight': 20,
        'description': (
            'Attackers exploit emotional urgency and fear of negative consequences '
            'to force quick decisions before the victim can verify authenticity.'
        ),
        'patterns': [
            r'\bimmediate\s+action\s+required\b',
            r'\byour\s+account\s+will\s+be\s+(?:deleted|closed|terminated|suspended)\b',
            r'\bwithin\s+24\s+hours\b',
            r'\bfinal\s+warning\b',
            r'\blegal\s+(?:action|notice|proceedings|arrest)\b',
            r'\bsecurity\s+breach\s+detected\b',
            r'\bunauthorized\s+login\s+attempt\b'
        ]
    },
    'fake_rewards': {
        'category': 'Lure & False Incentive',
        'severity': 'Medium',
        'weight': 15,
        'description': (
            'Promises of unexpected prizes, lottery winnings, or inherited fortunes '
            'are classic advance-fee scam lures.'
        ),
        'patterns': [
            r'\byou\s+have\s+won\b',
            r'\blottery\s+(?:winner|winning|jackpot)\b',
            r'\bclaim\s+your\s+(?:prize|reward|grant|cash)\b',
            r'\bselected\s+for\s+an\s+exclusive\s+reward\b',
            r'\bmillions?\s+of\s+dollars\b',
            r'\binheritance\s+(?:funds?|sum)\b'
        ]
    }
}


def extract_urls(text):
    """
    Finds, cleans, and extracts web URLs from the email body text.
    Strips trailing punctuation marks attached in conversational text.
    """
    url_pattern = r'(?:https?://|www\.)[^\s<>"\']+'
    raw_matches = re.findall(url_pattern, text, re.IGNORECASE)
    cleaned_urls = []
    for u in raw_matches:
        # Strip trailing punctuation marks commonly found at the end of sentences
        cleaned = re.sub(r'[\.,;:!?\)>\]\}"\']+$', '', u.strip())
        if cleaned and cleaned not in cleaned_urls:
            cleaned_urls.append(cleaned)
    return cleaned_urls


def inspect_sender(sender_email):
    """
    Analyzes the sender's email address for common spoofing anomalies.
    Returns a list of warning dictionaries.
    """
    warnings = []
    sender_clean = sender_email.strip().lower()

    if not sender_clean or '@' not in sender_clean:
        warnings.append({
            'category': 'Sender Anomaly',
            'severity': 'Medium',
            'title': 'Invalid or Missing Sender Format',
            'description': 'The sender address does not follow valid email formatting (user@domain.com).',
            'match': sender_email or 'Blank'
        })
        return warnings, 15

    parts = sender_clean.split('@')
    if len(parts) != 2:
        return warnings, 0

    user_part, domain_part = parts[0], parts[1]

    # Check for suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain_part.endswith(tld):
            warnings.append({
                'category': 'Sender Domain Threat',
                'severity': 'High',
                'title': f'High-Risk Top-Level Domain ({tld})',
                'description': f'The domain extension "{tld}" is statistically associated with disposable phishing campaigns.',
                'match': domain_part
            })
            break

    # Check for deceptive brand impersonation inside free or mismatch domains
    free_email_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
    for brand in HIGH_VALUE_TARGETS:
        # Check if brand name is in username part while using a free mail provider
        if brand in user_part and domain_part in free_email_providers:
            warnings.append({
                'category': 'Sender Spoofing',
                'severity': 'Critical',
                'title': f'Free Mail Impersonating Enterprise Brand ({brand.capitalize()})',
                'description': (
                    f'The sender is claiming to represent "{brand.capitalize()}" while sending from '
                    f'a free consumer email service (@{domain_part}). Legitimate corporate notices use their official domain.'
                ),
                'match': sender_email
            })
            break
        # Check if brand name is combined with hyphens or lookalike domain
        elif brand in domain_part and domain_part not in [f"{brand}.com", f"{brand}.org", f"{brand}.net"]:
            warnings.append({
                'category': 'Typosquatting / Lookalike Domain',
                'severity': 'Critical',
                'title': f'Deceptive Brand Domain Variation ({brand.capitalize()})',
                'description': (
                    f'Domain "{domain_part}" contains a major brand name "{brand}" '
                    'combined with extra keywords or hyphens to deceive users.'
                ),
                'match': domain_part
            })
            break

    sender_score = sum(30 if w['severity'] == 'Critical' else 15 for w in warnings)
    return warnings, sender_score


def analyze_single_url(raw_url):
    """
    Performs safe, offline heuristic decomposition and inspection of a single URL.
    Does NOT initiate any network connection or DNS request.
    Evaluates indicators: IP addresses, URL shorteners, lookalike/misleading domains,
    subdomain brand spoofing, high-risk TLDs, and protocol security.
    """
    findings = []

    # Normalize for parsing
    normalized = raw_url if raw_url.startswith(('http://', 'https://')) else 'http://' + raw_url
    try:
        parsed = urlparse(normalized)
    except Exception:
        return {
            'url': raw_url,
            'hostname': 'Malformed',
            'protocol': 'UNKNOWN',
            'status': 'Suspicious',
            'badge_class': 'warning',
            'flag_count': 1,
            'is_multi_indicator': False,
            'findings': [{
                'indicator': 'Malformed URL Syntax',
                'severity': 'Medium',
                'reason': 'The URL cannot be parsed cleanly according to standard RFC specifications.',
                'caution_note': 'Malformed URLs are often used by attackers to cause parser differential bypasses.'
            }],
            'verdict': 'Suspicious URL Structure (Parser Error)'
        }

    hostname = (parsed.hostname or '').lower()
    protocol = parsed.scheme.lower()
    path = parsed.path or ''
    full_url_lower = raw_url.lower()

    # 1. Direct IP Address Hostname
    ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, hostname):
        findings.append({
            'indicator': 'Direct IP Address Used as Host',
            'severity': 'High',
            'reason': (
                f"The link directs directly to numeric IP address '{hostname}' instead of a registered domain. "
                "Attackers use direct IP hosting to evade domain reputation filters and DNS blacklists."
            ),
            'caution_note': 'Legitimate organizations host public services on registered domain names, not raw IP addresses.'
        })

    # 2. URL Shortener Service (Caution only if single indicator)
    if hostname in URL_SHORTENERS:
        findings.append({
            'indicator': 'Obfuscated Link (URL Shortener)',
            'severity': 'Medium',
            'reason': (
                f"The service '{hostname}' is a URL shortener that masks the real destination URL. "
                "Attackers use shorteners so victims cannot inspect the final destination before clicking."
            ),
            'caution_note': 'Single Indicator Note: Shorteners are common in social media, so a shortener alone warrants caution rather than immediate proof of malice.'
        })

    # 3. Subdomain Brand Spoofing (e.g. login.microsoft.com.account-portal.com)
    for brand in HIGH_VALUE_TARGETS:
        if brand in hostname:
            parts = hostname.split('.')
            if len(parts) >= 3 and parts[-2] != brand:
                findings.append({
                    'indicator': f"Subdomain Deception / Brand Spoofing ({brand.capitalize()})",
                    'severity': 'High',
                    'reason': (
                        f"The trusted brand name '{brand.capitalize()}' is placed in the subdomain or prefix of '{hostname}', "
                        f"while the actual registered domain is '{parts[-2]}.{parts[-1]}'. Attackers do this to deceive victims who only skim the start of the URL."
                    ),
                    'caution_note': 'Always verify the domain immediately before the final extension (TLD).'
                })
                break

    # 4. Typosquatting / Character Substitution (e.g. paypa1, micros0ft, amaz0n)
    typosquat_targets = {
        'paypa1': 'PayPal', 'micros0ft': 'Microsoft', 'g00gle': 'Google',
        'amaz0n': 'Amazon', 'app1e': 'Apple', 'netf1ix': 'Netflix',
        'wellsfarg0': 'Wells Fargo', 'faceb00k': 'Facebook'
    }
    for typo, original in typosquat_targets.items():
        if typo in hostname:
            findings.append({
                'indicator': f"Typosquatting / Character Substitution ({original})",
                'severity': 'High',
                'reason': (
                    f"Domain contains '{typo}', a character substitution trick (e.g. '0' for 'o', '1' for 'l') "
                    f"designed to visually impersonate '{original}'."
                ),
                'caution_note': 'Carefully inspect spelling in URLs for lookalike glyphs and homoglyphs.'
            })
            break

    # 5. Brand-Keyword Combination (e.g. paypal-update-account.com)
    for brand in HIGH_VALUE_TARGETS:
        if brand in hostname and hostname not in [f"{brand}.com", f"www.{brand}.com"]:
            if not any(f['indicator'].startswith(('Subdomain Deception', 'Typosquatting')) for f in findings):
                findings.append({
                    'indicator': f"Deceptive Brand-Keyword Combination ({brand.capitalize()})",
                    'severity': 'High',
                    'reason': (
                        f"Domain '{hostname}' combines the brand name '{brand.capitalize()}' with extra keywords or hyphens "
                        "on an unauthorized, unverified third-party host."
                    ),
                    'caution_note': 'Legitimate enterprise notices will direct to the official domain, not hyphenated lookalikes.'
                })
                break

    # 6. Embedded Credentials / Redirect Trick (@ in URL)
    if '@' in raw_url.split('?')[0]:
        findings.append({
            'indicator': 'Embedded Credentials / Redirect Obfuscation (@ Trick)',
            'severity': 'High',
            'reason': (
                "The URL contains an '@' character before the host. In browser specifications, "
                "everything before '@' is treated as username data, and the browser navigates to the host after '@'."
            ),
            'caution_note': 'Attackers use this to trick users into thinking they are visiting the domain before the @ sign.'
        })

    # 7. High-Risk Disposable TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            findings.append({
                'indicator': f"High-Risk Top-Level Domain ({tld})",
                'severity': 'Medium',
                'reason': (
                    f"The link points to a domain extension '{tld}' statistically associated with disposable phishing campaigns."
                ),
                'caution_note': 'Single Indicator Note: Some legitimate developers use modern TLDs, so an unusual TLD alone is an indicator for caution rather than guaranteed malware.'
            })
            break

    # 8. Insecure Protocol on Sensitive Path
    sensitive_keywords = ['login', 'signin', 'verify', 'account', 'password', 'banking', 'reset', 'update', 'billing', 'auth']
    if protocol == 'http':
        is_sensitive = any(kw in path.lower() or kw in full_url_lower for kw in sensitive_keywords)
        if is_sensitive:
            findings.append({
                'indicator': 'Insecure HTTP on Authentication/Sensitive Path',
                'severity': 'Medium',
                'reason': (
                    f"The link uses unencrypted 'http://' to request sensitive actions ('{path}'). "
                    "Legitimate institutions use HTTPS encryption to protect credentials from Man-in-the-Middle interception."
                ),
                'caution_note': 'Never enter credentials or personal data over unencrypted HTTP.'
            })

    # Multi-Indicator Classification & Explainable Verdict
    flag_count = len(findings)
    if flag_count == 0:
        status = 'Clean / Low Suspicion'
        badge_class = 'safe'
        verdict = 'No suspicious offline patterns detected on this link.'
    elif flag_count == 1:
        status = 'Suspicious (1 Indicator — Exercise Caution)'
        badge_class = 'warning'
        verdict = (
            'Single indicator detected. This does not definitively prove malice on its own, '
            'but warrants secondary verification before clicking.'
        )
    else:
        status = f'High Risk ({flag_count} Correlated Threat Indicators)'
        badge_class = 'danger'
        verdict = (
            'Multiple corroborating threat indicators detected on this URL. '
            'Strong probability of an active phishing or credential theft lure.'
        )

    return {
        'url': raw_url,
        'hostname': hostname,
        'protocol': protocol.upper() if protocol else 'UNKNOWN',
        'status': status,
        'badge_class': badge_class,
        'flag_count': flag_count,
        'is_multi_indicator': flag_count > 1,
        'findings': findings,
        'verdict': verdict
    }


def inspect_links(urls):
    """
    Examines all extracted URLs using safe, offline multi-indicator heuristics.
    Returns:
    - warnings: list of formatted threat warnings for the main report
    - link_score: explainable weighted score contribution
    - detailed_url_results: per-URL inspection reports
    - url_summary: counts of clean, suspicious, and high-risk URLs
    """
    detailed_url_results = []
    warnings = []
    
    suspicious_count = 0
    high_risk_count = 0

    for raw_url in urls:
        analysis = analyze_single_url(raw_url)
        detailed_url_results.append(analysis)

        if analysis['badge_class'] == 'danger':
            high_risk_count += 1
            reasons_summary = "; ".join(f['indicator'] for f in analysis['findings'])
            warnings.append({
                'category': 'High-Risk Malicious Link',
                'severity': 'Critical',
                'title': f"Multi-Indicator Phishing URL ({analysis['hostname']})",
                'description': (
                    f"URL '{analysis['url']}' triggered {analysis['flag_count']} correlated threat indicators: {reasons_summary}. "
                    "Multiple independent heuristics corroborate deceptive intent."
                ),
                'match': analysis['url']
            })
        elif analysis['badge_class'] == 'warning':
            suspicious_count += 1
            for f in analysis['findings']:
                warnings.append({
                    'category': 'Suspicious Link Pattern',
                    'severity': f['severity'],
                    'title': f['indicator'],
                    'description': f['reason'] + " " + f['caution_note'],
                    'match': analysis['url']
                })

    # Explainable Capped Score Contribution:
    # High risk URLs: 25 pts each (capped at 35)
    # Suspicious URLs: 10 pts each (capped at 15)
    link_score = min(high_risk_count * 25, 35) + min(suspicious_count * 10, 15)
    link_score = min(link_score, 40)

    url_summary = {
        'total': len(urls),
        'clean': len([u for u in detailed_url_results if u['badge_class'] == 'safe']),
        'suspicious': suspicious_count,
        'high_risk': high_risk_count
    }

    return warnings, link_score, detailed_url_results, url_summary


def analyze_email(sender, content):
    """
    Main analysis pipeline orchestrator.
    Executes rule-based checks, aggregates warning triggers,
    computes an interpretable risk score (0-100), and formulates recommendations.
    """
    warnings = []
    total_score = 0

    full_text = f"{sender}\n{content}"

    # 1. Sender Address Verification
    sender_warnings, s_score = inspect_sender(sender)
    warnings.extend(sender_warnings)
    total_score += s_score

    # 2. Safe Offline Link & URL Inspection
    extracted_urls = extract_urls(content)
    link_warnings, l_score, detailed_urls, url_summary = inspect_links(extracted_urls)
    warnings.extend(link_warnings)
    total_score += l_score

    # 3. Keyword & Semantic Urgency Matching
    for rule_key, rule_data in THREAT_PATTERNS.items():
        matched_instances = []
        for pat in rule_data['patterns']:
            matches = re.findall(pat, full_text, re.IGNORECASE)
            if matches:
                matched_instances.extend(matches)

        if matched_instances:
            unique_matches = list(dict.fromkeys(matched_instances))[:3]
            warnings.append({
                'category': rule_data['category'],
                'severity': rule_data['severity'],
                'title': f"Detected {rule_data['category']}",
                'description': rule_data['description'],
                'match': ", ".join(f'"{m}"' for m in unique_matches)
            })
            total_score += rule_data['weight']

    # 4. Normalize Score to 0 - 100 Scale
    risk_score = min(max(total_score, 0), 100)

    # 5. Determine Overall Risk Rating & Remediation
    if risk_score >= 60:
        risk_level = 'Dangerous (High Phishing Probability)'
        badge_class = 'danger'
        verdict_summary = (
            'Severe security threats detected. This email exhibits strong indicators '
            'of a targeted phishing attack or credential theft campaign. Do NOT interact.'
        )
    elif risk_score >= 25:
        risk_level = 'Suspicious (Proceed with Caution)'
        badge_class = 'warning'
        verdict_summary = (
            'Potential risk indicators identified. The email uses urgent language or unusual '
            'sender patterns. Verify via a secondary channel before clicking any links.'
        )
    else:
        risk_level = 'Safe / Low Threat'
        badge_class = 'safe'
        verdict_summary = (
            'No standard phishing patterns or high-risk indicators were detected. '
            'Always practice standard cyber hygiene when viewing attachments.'
        )

    # Recommended Security Actions
    recommendations = []
    if risk_score >= 60:
        recommendations.append('Do NOT click any hyperlinks or open any attachments.')
        recommendations.append('Do NOT reply or attempt to negotiate with the sender.')
        recommendations.append('Report this email immediately to your organization’s IT Security / SOC team.')
        recommendations.append('If you already entered credentials, immediately change your password and revoke active sessions.')
    elif risk_score >= 25:
        recommendations.append('Contact the purported sender using an official, independently verified phone number or portal.')
        recommendations.append('Hover over links to verify their true destination before clicking.')
        recommendations.append('Ensure multi-factor authentication (MFA) is active on your accounts.')
    else:
        recommendations.append('Email appears clean, but remain vigilant for zero-day phishing variants.')
        recommendations.append('Verify sender domain matches the expected organization.')

    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'badge_class': badge_class,
        'verdict_summary': verdict_summary,
        'warnings': warnings,
        'total_warnings': len(warnings),
        'extracted_urls_count': len(extracted_urls),
        'url_analysis': detailed_urls,
        'url_summary': url_summary,
        'recommendations': recommendations
    }


# -------------------------------------------------------------------------
# PRESET SAMPLE EMAILS FOR HANDS-ON TESTING
# -------------------------------------------------------------------------
SAMPLE_EMAILS = {
    'sample_phishing_bank': {
        'title': '🚨 PayPal Account Suspension (Phishing)',
        'description': 'Credential harvesting attempt using brand spoofing, urgent fear tactics, and a fake IP link.',
        'sender': 'security-alert@paypa1-support-portal.xyz',
        'content': (
            "Subject: FINAL WARNING: Immediate Action Required - PayPal Account Suspended\n\n"
            "Dear Customer,\n\n"
            "We have detected unauthorized login attempts to your PayPal account from an unrecognized IP address. "
            "For your protection, your account has been temporarily restricted.\n\n"
            "Your account will be terminated within 24 hours unless you confirm your identity immediately.\n\n"
            "Click here to unlock and verify your password and current credentials:\n"
            "http://192.168.1.105/paypal-login/verify.php\n\n"
            "Failure to complete this verification will result in permanent account closure and forfeiture of funds.\n\n"
            "Sincerely,\n"
            "PayPal Security & Fraud Defense Team"
        )
    },
    'sample_bec_ceo': {
        'title': '💼 Urgent Wire Transfer / CEO Fraud (BEC)',
        'description': 'Business Email Compromise (BEC) simulating an executive requesting an urgent wire payment.',
        'sender': 'ceo.executive.office@gmail.com',
        'content': (
            "Subject: Confidential: Immediate Wire Transfer Needed Today\n\n"
            "Hi Team,\n\n"
            "I am currently in an all-day confidential board meeting and cannot take phone calls.\n\n"
            "We have an overdue invoice for our new acquisition partners. "
            "Please process an immediate wire transfer of $48,500 today before 3:00 PM.\n\n"
            "The outstanding payment must be cleared today to avoid legal action and breach of contract. "
            "Reply directly to this email with the wire confirmation number as soon as it is sent.\n\n"
            "Keep this strictly confidential between us.\n\n"
            "Best Regards,\n"
            "Mark Henderson\n"
            "Chief Executive Officer"
        )
    },
    'sample_lottery_scam': {
        'title': '🎁 International Lottery Reward (Scam)',
        'description': 'Classic advance-fee fraud promising millions of dollars via an obfuscated link.',
        'sender': 'claims-department@euromillions-promo.tk',
        'content': (
            "Subject: Congratulations! You have won $2,500,000 USD\n\n"
            "Attention Lucky Winner,\n\n"
            "You have won $2,500,000 in the International Euro Millions Lottery jackpot draw. "
            "Your email was selected for an exclusive reward from our international promotion pool.\n\n"
            "To claim your prize, please click the secure link below and submit your personal banking details:\n"
            "http://bit.ly/claim-jackpot-reward-2026\n\n"
            "Please respond within 48h to claim your inheritance fund and grant disbursement.\n\n"
            "Foreign Disbursement Director,\n"
            "Mr. Arthur Sterling"
        )
    },
    'sample_lookalike_domain': {
        'title': '🎣 Microsoft 365 Lookalike / Subdomain Spoofing',
        'description': 'Targeted phishing demonstrating subdomain deception, disposable TLD, and password reset lure.',
        'sender': 'admin@office365-security-alert.xyz',
        'content': (
            "Subject: Microsoft 365: Urgent Action Required - Password Expiration Notice\n\n"
            "Dear User,\n\n"
            "Your Microsoft 365 enterprise account password will expire within 24 hours. "
            "To maintain access to your corporate email, OneDrive, and Teams files, you must verify your login credentials immediately.\n\n"
            "Click below to confirm your password and update your security keys:\n"
            "http://login.microsoft.com.account-verification-portal.xyz/auth/reset\n\n"
            "Unverified accounts will be suspended automatically.\n\n"
            "Microsoft Security Operations"
        )
    },
    'sample_legit_corporate': {
        'title': '✅ Legitimate Project Meeting Update (Safe)',
        'description': 'Normal internal office communication without urgent pressure or malicious links.',
        'sender': 'sarah.jenkins@acmecorp.com',
        'content': (
            "Subject: Team Sync: Q3 Cybersecurity Project Roadmap\n\n"
            "Hi everyone,\n\n"
            "Just a reminder that our weekly project synchronization meeting is scheduled for tomorrow, "
            "Thursday at 10:00 AM in Conference Room B and on Microsoft Teams.\n\n"
            "We will review the sprint backlog, discuss the authentication refactoring progress, "
            "and plan next week's deliverables. Please update your Jira tickets prior to the call.\n\n"
            "The agenda document is shared in our internal SharePoint workspace:\n"
            "https://sharepoint.acmecorp.com/teams/q3-roadmap\n\n"
            "Looking forward to catching up with everyone tomorrow.\n\n"
            "Warm regards,\n"
            "Sarah Jenkins\n"
            "Senior Project Manager | Acme Corporation\n"
            "sarah.jenkins@acmecorp.com"
        )
    }
}


# -------------------------------------------------------------------------
# FLASK WEB CONTROLLERS / ROUTES
# -------------------------------------------------------------------------
@app.route('/', methods=['GET', 'POST'])
def home():
    """
    Renders the web interface.
    Handles both initial GET request and POST submission from the analysis form.
    """
    analysis_result = None
    sender = ''
    content = ''

    if request.method == 'POST':
        sender = request.form.get('sender', '').strip()
        content = request.form.get('content', '').strip()

        if sender or content:
            analysis_result = analyze_email(sender, content)

    return render_template(
        'index.html',
        analysis=analysis_result,
        sender=sender,
        content=content,
        samples=SAMPLE_EMAILS
    )


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    REST API endpoint for asynchronous or programmatic email analysis.
    Useful for students learning frontend fetch/AJAX or integrating with scripts.
    """
    data = request.get_json(silent=True) or {}
    sender = data.get('sender', '').strip()
    content = data.get('content', '').strip()

    if not sender and not content:
        return jsonify({'error': 'Please provide sender or content for analysis'}), 400

@app.route('/report')
def view_report():
    """
    Renders the complete Anna University format academic project report.
    Users can read, print, or save to PDF directly in their browser.
    """
    report_path = os.path.join(app.root_path, 'PROJECT_REPORT.html')
    if os.path.exists(report_path):
        with open(report_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Project report file not found.", 404


@app.route('/download-report')
def download_report():
    """
    Directly downloads the project report file to the user's computer.
    """
    report_path = os.path.join(app.root_path, 'PROJECT_REPORT.html')
    return send_file(report_path, as_attachment=True, download_name='CyberSentinel_AI_Project_Report.html')


if __name__ == '__main__':
    # Running locally in debug mode for development and learning
    print("==================================================================")
    print("🛡️  CyberSentinel AI — Email Threat Detection System")
    print("🚀  Starting local Flask development server at: http://127.0.0.1:5000")
    print("💡  Press CTRL+C to stop the server")
    print("==================================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)
