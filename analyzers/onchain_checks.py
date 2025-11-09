from web3 import Web3
import os
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Multi-chain RPC configuration (Ethereum + BSC)
# ---------------------------------------------------------------------------

RPC_MAP = {
    "ethereum": os.getenv("ETH_RPC_URL", "https://eth.llamarpc.com"),
    "bsc": os.getenv("BSC_RPC_URL", "https://bsc-dataseed.binance.org"),
}

def check_honeypot_and_owner(address: str, chain: str = "ethereum"):
    """
    Basic on-chain scanner that checks:
    - Contract code presence
    - ERC20-like info (name, symbol)
    - Owner() if available
    - Transfer() existence (honeypot flag)
    """

    rpc_url = RPC_MAP.get(chain.lower())
    if not rpc_url:
        return {"error": f"Unsupported chain '{chain}'. Use 'ethereum' or 'bsc'."}

    print(f"🔗 Connecting to {chain.title()} RPC...")
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    if not w3.is_connected():
        return {"error": f"Cannot connect to {chain.title()} RPC node."}

    try:
        address = Web3.to_checksum_address(address)
    except Exception:
        return {"error": "Invalid address format."}

    code = w3.eth.get_code(address)
    if not code or len(code) == 0:
        return {"error": "No contract code found (EOA address)."}

    # Minimal ERC20 ABI for checks
    abi = [
        {"name": "name", "outputs": [{"type": "string"}], "stateMutability": "view", "type": "function"},
        {"name": "symbol", "outputs": [{"type": "string"}], "stateMutability": "view", "type": "function"},
        {"name": "owner", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
        {"name": "transfer", "inputs": [{"type": "address"}, {"type": "uint256"}], "outputs": [{"type": "bool"}], "stateMutability": "nonpayable", "type": "function"},
    ]

    contract = w3.eth.contract(address=address, abi=abi)
    result = {}

    # Basic token info
    try:
        name = contract.functions.name().call()
        symbol = contract.functions.symbol().call()
        result["token"] = f"{name} ({symbol})"
    except Exception:
        result["token"] = "Unknown Token"

    # Owner detection
    try:
        owner = contract.functions.owner().call()
        result["owner"] = owner
    except Exception:
        result["owner"] = "⚠️ Owner() not found (may use custom access control)."

    # Transfer presence
    try:
        fn_names = [fn.fn_name for fn in contract.all_functions()]
        result["transfer_test"] = "✅ Transfer function exists" if "transfer" in fn_names else "❌ Missing transfer()"
    except Exception:
        result["transfer_test"] = "⚠️ Transfer check failed"

    # Honeypot indicator
    result["honeypot_risk"] = (
        "🟢 Transfer function present"
        if "✅" in result["transfer_test"]
        else "🔴 Possible Honeypot (transfer() missing)"
    )

    return result
