# 🛡️ Phishing URL Detector

A **Mini Cyber Defense Tool** that analyzes URLs for phishing indicators using heuristic scoring.  
Built with Python (CLI) + HTML/CSS/JS (Web UI) — zero external dependencies.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square&logo=python)
![HTML](https://img.shields.io/badge/HTML-CSS-JS-orange?style=flat-square&logo=html5)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![No Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square)

---

## 🌟 Features

- ✅ **HTTPS Check** — Detects unencrypted HTTP connections
- ✅ **Suspicious Keyword Detection** — Flags phishing words (login, verify, bank, etc.)
- ✅ **URL Length Analysis** — Long URLs are a common phishing trick
- ✅ **Deceptive Symbol Detection** — Catches `@` symbols and excessive hyphens
- ✅ **Domain Trust Verification** — Identifies trusted vs. suspicious domains/TLDs
- ✅ **Risk Score (0–100)** — Clear verdict: Safe / Suspicious / High Risk

---

## 📁 Project Structure

```
phishing-url-detector/
│
├── detector.py          # Core Python CLI tool
├── test_detector.py     # Unit tests
├── index.html           # Web UI (open in browser, no server needed)
├── requirements.txt     # No external deps (stdlib only)
├── .gitignore
└── README.md
```

---

## 🚀 Getting Started

### Python CLI

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/phishing-url-detector.git
cd phishing-url-detector

# Run interactive mode
python detector.py

# Or pass a URL directly
python detector.py https://example.com/login
```

### Web UI

Just open `index.html` in any browser — no server required!

---

## 🔍 How It Works

The tool runs **5 heuristic checks** and produces a **risk score (0–100)**:

| Check | Description | Max Score |
|-------|-------------|-----------|
| HTTPS | Missing HTTPS = unencrypted = risky | +20 |
| Keywords | login, verify, bank, paytm, etc. | +30 |
| URL Length | >75 chars = suspicious, >100 = very long | +20 |
| Tricks | `@` symbol or 2+ hyphens in domain | +25 |
| Domain/TLD | Suspicious TLDs (.xyz, .tk) or trusted domains | ±15 |

**Verdict:**
- 🟢 **0–15** → Likely Safe
- 🟡 **16–45** → Suspicious
- 🔴 **46–100** → High Risk / Phishing Likely

---

## 🧪 Run Tests

```bash
python test_detector.py
```

All 11 unit tests cover safe URLs, suspicious URLs, high-risk cases, and edge cases.

---

## 📸 Demo

### CLI Output
```
═══════════════════════════════════════════════════════
       🛡️  PHISHING URL DETECTOR  v1.0
       Mini Cyber Defense Tool
═══════════════════════════════════════════════════════

  Enter URL: http://paytm-secure-login.xyz/verify

───────────────────────────────────────────────────────
  🔍 PHISHING URL ANALYSIS REPORT
───────────────────────────────────────────────────────
  URL     : http://paytm-secure-login.xyz/verify
  Score   : 75/100
  Verdict : 🔴  HIGH RISK — PHISHING LIKELY
───────────────────────────────────────────────────────
  ISSUES FOUND:
    ❌ No HTTPS — connection is unencrypted (risky)
    ⚠️  Suspicious keywords found: login, verify, secure
    ⚠️  Multiple hyphens (2) in domain — looks suspicious
    ❌ Suspicious TLD detected (e.g., .xyz, .tk, .ml)
───────────────────────────────────────────────────────
  💡 Tip: Multiple phishing indicators found! Do NOT visit this site.
───────────────────────────────────────────────────────
```

---

## 🧠 Security Concepts Covered

- **Phishing Attack Detection**
- **Social Engineering Awareness**
- **URL Heuristic Analysis**
- **Threat Scoring System**
- **Domain Trust Verification**
- **SSL/TLS Security Basics**

---

## 🔮 Future Improvements

- [ ] VirusTotal API integration for live threat lookup
- [ ] WHOIS domain age check (new domains = risky)
- [ ] IP address URL detection
- [ ] Export report as PDF
- [ ] Browser extension version

---

## 📄 License

MIT License — feel free to use, modify, and distribute.

---

## 👤 Author

**Your Name**  
[GitHub](https://github.com/YOUR_USERNAME) · [LinkedIn](https://linkedin.com/in/YOUR_USERNAME)

> ⭐ Star this repo if you found it useful!
