import argparse
from colorama import Fore, Style
from analyzers.solidity_patterns import analyze_contract, save_scan_report
from analyzers.onchain_checks import check_honeypot_and_owner

# ---------------------------------------------------------------------------
# Smart Contract Sentinel - Main Entry Point
# ---------------------------------------------------------------------------
# This CLI tool scans deployed smart contracts for potential risks such as
# honeypots, blacklist logic, unrestricted minting, or missing ownership
# renouncement. It performs both:
#   - Static analysis (source code inspection)
#   - Live on-chain checks (RPC-based metadata)
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ Smart Contract Sentinel – Analyze deployed contracts for potential risks."
    )
    parser.add_argument(
        "--address",
        required=True,
        help="Contract address to analyze (e.g., 0x1234...)"
    )
    parser.add_argument(
        "--chain",
        default="ethereum",
        help="Target blockchain (ethereum, bsc, polygon). Default: ethereum"
    )
    args = parser.parse_args()

    # ------------------ Start Static Analysis ------------------
    print(f"{Fore.CYAN}🔍 Scanning {args.address} on {args.chain.title()}...{Style.RESET_ALL}")
    results = analyze_contract(args.address, args.chain)

    print(f"\n{Fore.WHITE}=== Static Scan Results ==={Style.RESET_ALL}")
    for r in results:
        color = (
            Fore.RED if r["severity"] == "High"
            else Fore.YELLOW if r["severity"] == "Medium"
            else Fore.GREEN if r["severity"] == "Low"
            else Fore.CYAN
        )
        print(f"{color}{r['status']}{Style.RESET_ALL} - {r['message']}")

    # ------------------ On-Chain Analysis ------------------
    print(f"\n{Fore.MAGENTA}=== On-Chain Analysis ==={Style.RESET_ALL}")
    try:
        onchain_results = check_honeypot_and_owner(args.address)
        for key, val in onchain_results.items():
            print(f"{Fore.MAGENTA}{key}:{Style.RESET_ALL} {val}")
    except Exception as e:
        print(f"{Fore.RED}❌ On-chain analysis failed:{Style.RESET_ALL} {e}")
        onchain_results = {"error": str(e)}

    # ------------------ Save Combined Report ------------------
    combined_report = results + [{"status": "🔗 On-chain", "message": str(onchain_results), "severity": "Info"}]
    save_scan_report(args.address, args.chain, combined_report)

    print(f"\n{Fore.CYAN}Scan complete ✅{Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# Program Entry
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
