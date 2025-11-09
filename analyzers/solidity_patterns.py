import requests
import json
import os
from datetime import datetime

from typing import List, Dict

# ---------------------------------------------------------------------------
# Smart Contract Sentinel - Analyzer Module
# ---------------------------------------------------------------------------
# This module fetches verified Solidity source code from public explorers
# (Blockscout-based) and scans for common risk patterns that indicate
# potential honeypot, rug pull, or ownership issues.
# ---------------------------------------------------------------------------

def get_contract_source(address: str, chain: str = "ethereum") -> str:
    """
    Fetch verified contract source code using the appropriate Blockscout explorer.
    Returns an empty string if the contract is unverified or not found.
    """
    # Choose the correct Blockscout domain based on the chain
    chain_domains = {
        "ethereum": "eth.blockscout.com",
        "bsc": "bsc.blockscout.com",
        "polygon": "polygon.blockscout.com",
    }

    domain = chain_domains.get(chain.lower(), "eth.blockscout.com")
    url = f"https://{domain}/api?module=contract&action=getsourcecode&address={address}"

    try:
        resp = requests.get(url, timeout=15)
        data = resp.json()
    except Exception as e:
        print("❌ Failed to connect to Blockscout:", e)
        return ""

    if not data or "result" not in data:
        print("❌ Unexpected API response:", data)
        return ""

    result = data.get("result")
    if isinstance(result, list) and result:
        result = result[0]
    elif isinstance(result, str):
        print(f"⚠️ API returned message: {result}")
        return ""
    elif not isinstance(result, dict):
        print("❌ Unexpected result format:", type(result))
        return ""

    source_code = result.get("SourceCode") or ""
    if source_code:
        print(f"✅ Contract source fetched successfully from {domain}.")
        return source_code
    else:
        print("⚠️ Contract found but not verified or no source available.")
        return ""


# ---------------------------------------------------------------------------
# Analyze Solidity source for risk patterns and compute a risk score
# ---------------------------------------------------------------------------

def analyze_contract(address: str, chain: str) -> List[Dict]:
    """
    Fetch contract, scan for security patterns, and assign a risk score.
    """

    # ----------------- Fetch contract -----------------
    source_code = get_contract_source(address, chain)
    results = []
    risk_score = 100  # start high and deduct on risky findings

    # ----------------- Handle unverified contracts -----------------
    if not source_code:
        results.append({
            "status": "❌ Critical",
            "message": "Contract not verified — cannot review source.",
            "severity": "High"
        })
        risk_score -= 80
        results.append({
            "status": "⚠️ Risk",
            "message": f"Overall Risk Score: {max(risk_score,0)}/100 (Critical)",
            "severity": "High"
        })
        return results

    # ----------------- Pattern checks -----------------
    checks = {
        "onlyOwner": ("✅ Contains access control using onlyOwner.", 0),
        "mint": ("⚠️ Mint function found (check if restricted).", -20),
        "blacklist": ("⚠️ Blacklist logic detected (potential sell restriction).", -15),
        "tx.origin": ("🚨 Uses tx.origin — potential phishing risk.", -40),
        "renounceOwnership": ("✅ Ownership can be renounced.", +20),
    }

    issues = 0
    for pattern, (message, impact) in checks.items():
        if pattern.lower() in source_code.lower():
            severity = (
                "High" if "🚨" in message
                else "Medium" if "⚠️" in message
                else "Low"
            )
            results.append({
                "status": message.split(" ")[0],
                "message": message,
                "severity": severity
            })
            risk_score += impact
            if impact < 0:
                issues += 1

    # ----------------- Safe / No issue case -----------------
    if issues == 0:
        results.append({
            "status": "✅ Safe",
            "message": "No known risk patterns detected.",
            "severity": "Low"
        })
        risk_score += 10

    # ----------------- Clamp risk score between 0–100 -----------------
    risk_score = max(0, min(100, risk_score))

    # ----------------- Risk level labels -----------------
    risk_label = (
        "🟢 Low Risk" if risk_score >= 80
        else "🟡 Moderate Risk" if risk_score >= 50
        else "🔴 High Risk"
    )

    # ----------------- Summary result -----------------
    results.append({
        "status": "📊 Summary",
        "message": f"Verified: ✅ | Issues Found: {issues} | Overall Risk: {risk_score}/100 ({risk_label})",
        "severity": "Info"
    })

    return results

def save_scan_report(address: str, chain: str, results: List[Dict]):
    """
    Save scan results to a timestamped JSON file.
    """
    # Ensure reports directory exists
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{chain}_{address[:6]}_{timestamp}.json"

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(f"\n📝 Report saved successfully → {filename}")
    except Exception as e:
        print("❌ Failed to save report:", e)

# ---------------------------------------------------------------------------
# End of File
# ---------------------------------------------------------------------------
