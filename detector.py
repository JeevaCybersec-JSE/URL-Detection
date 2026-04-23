"""
Phishing URL Detector - CLI Tool
Author: Your Name
Description: Analyzes URLs for phishing indicators using heuristic scoring
"""

import re
import sys
from urllib.parse import urlparse

# ─────────────────────────────────────────
# Detection Config
# ─────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "paypal", "paytm", "password", "confirm",
    "signin", "credential", "wallet", "auth", "webscr"
]

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "wikipedia.org", "linkedin.com",
    "twitter.com", "facebook.com", "instagram.com", "netflix.com"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".top", ".click", ".work", ".party"
]

# ─────────────────────────────────────────
# Core Analysis Function
# ─────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """
    Analyzes a URL and returns a detailed phishing risk report.
    Returns a dict with score, verdict, checks, and tips.
    """

    if not url.startswith("http"):
        url = "http://" + url

    score = 0
    flags = []
    passed = []

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        full_url = url.lower()
    except Exception:
        return {"error": "Invalid URL. Please enter a valid web address."}

    # ── Check 1: HTTPS ──────────────────────────────
    if url.startswith("https://"):
        passed.append("✅ HTTPS encryption present")
    else:
        score += 20
        flags.append("❌ No HTTPS — connection is unencrypted (risky)")

    # ── Check 2: Suspicious Keywords ────────────────
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    if found_keywords:
        kw_score = min(len(found_keywords) * 10, 30)
        score += kw_score
        flags.append(f"⚠️  Suspicious keywords found: {', '.join(found_keywords)}")
    else:
        passed.append("✅ No suspicious keywords found")

    # ── Check 3: URL Length ──────────────────────────
    url_length = len(url)
    if url_length > 100:
        score += 20
        flags.append(f"⚠️  URL is very long ({url_length} chars) — common in phishing")
    elif url_length > 75:
        score += 10
        flags.append(f"⚠️  URL is moderately long ({url_length} chars)")
    else:
        passed.append(f"✅ URL length is normal ({url_length} chars)")

    # ── Check 4: Deceptive Tricks ───────────────────
    has_at = "@" in url
    dash_count = hostname.count("-")

    if has_at:
        score += 15
        flags.append("❌ '@' symbol in URL — common phishing trick to hide real domain")
    if dash_count >= 2:
        score += 10
        flags.append(f"⚠️  Multiple hyphens ({dash_count}) in domain — looks suspicious")
    if not has_at and dash_count < 2:
        passed.append("✅ No deceptive symbols or excessive hyphens")

    # ── Check 5: Domain Trust ────────────────────────
    is_trusted = any(
        hostname == td or hostname.endswith("." + td)
        for td in TRUSTED_DOMAINS
    )
    has_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)

    if is_trusted:
        score = max(0, score - 15)
        passed.append(f"✅ Domain is a known trusted site ({hostname})")
    elif has_suspicious_tld:
        score += 15
        flags.append(f"❌ Suspicious TLD detected (e.g., .xyz, .tk, .ml)")
    else:
        flags.append(f"⚠️  Unknown domain — could not verify trust ({hostname})")

    # ── Verdict ──────────────────────────────────────
    score = min(100, max(0, score))

    if score <= 15:
        verdict = "LIKELY SAFE"
        emoji = "🟢"
        tip = "No major red flags. Still verify the domain spelling before entering any credentials."
    elif score <= 45:
        verdict = "SUSPICIOUS"
        emoji = "🟡"
        tip = "Some warning signs detected. Do NOT enter passwords or personal info on this site."
    else:
        verdict = "HIGH RISK — PHISHING LIKELY"
        emoji = "🔴"
        tip = "Multiple phishing indicators found! Do NOT visit this site or share any information."

    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "emoji": emoji,
        "flags": flags,
        "passed": passed,
        "tip": tip
    }


# ─────────────────────────────────────────
# Pretty Print Report
# ─────────────────────────────────────────

def print_report(result: dict):
    if "error" in result:
        print(f"\n  ❌ Error: {result['error']}\n")
        return

    divider = "─" * 55

    print(f"\n{divider}")
    print(f"  🔍 PHISHING URL ANALYSIS REPORT")
    print(f"{divider}")
    print(f"  URL     : {result['url'][:60]}{'...' if len(result['url']) > 60 else ''}")
    print(f"  Score   : {result['score']}/100")
    print(f"  Verdict : {result['emoji']}  {result['verdict']}")
    print(f"{divider}")

    if result["flags"]:
        print("  ISSUES FOUND:")
        for flag in result["flags"]:
            print(f"    {flag}")

    if result["passed"]:
        print("  CHECKS PASSED:")
        for p in result["passed"]:
            print(f"    {p}")

    print(f"{divider}")
    print(f"  💡 Tip: {result['tip']}")
    print(f"{divider}\n")


# ─────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────

def main():
    print("\n" + "═" * 55)
    print("       🛡️  PHISHING URL DETECTOR  v1.0")
    print("       Mini Cyber Defense Tool")
    print("═" * 55)

    # Accept URL from command line or prompt
    if len(sys.argv) > 1:
        url = sys.argv[1]
        result = analyze_url(url)
        print_report(result)
    else:
        print("\n  Type a URL to analyze. Type 'quit' to exit.\n")
        while True:
            try:
                url = input("  Enter URL: ").strip()
                if url.lower() in ("quit", "exit", "q"):
                    print("\n  👋 Stay safe online!\n")
                    break
                if url:
                    result = analyze_url(url)
                    print_report(result)
            except KeyboardInterrupt:
                print("\n\n  👋 Stay safe online!\n")
                break


if __name__ == "__main__":
    main()
